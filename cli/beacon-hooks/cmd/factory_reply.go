package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/asymptote-labs/agent-beacon/cli/beacon-hooks/internal/logging"
	"github.com/asymptote-labs/agent-beacon/cli/beacon-hooks/internal/state"
)

// factoryTranscriptTailBytes bounds how much of a Droid transcript the Stop hook reads. Only the
// last message record matters, and one record is far smaller than this.
const factoryTranscriptTailBytes = 1 << 20

// factoryReply is the final assistant message of a Droid turn as its transcript records it.
type factoryReply struct {
	id   string
	text string
}

// factoryTranscriptReply reads the turn's final reply from a Factory Droid session transcript.
//
// Droid's Stop payload carries no reply text, only transcript_path, so this is the one place a live
// hook can learn what the agent said. A transcript can lag the hook that names it, so a reply is
// returned only when the transcript's newest message record is an assistant message that has text
// and no tool call. A turn's final answer never ends on a tool call, so an assistant message that
// does is one the turn has not finished with -- the transcript is behind -- and reporting it as the
// answer would be wrong. Anything else returns false and the session sync reads the reply later.
//
// Only a regular .jsonl file is read, from its last factoryTranscriptTailBytes, and any failure
// returns nothing: a missed reply costs one event, a stalled hook costs the agent's turn.
func factoryTranscriptReply(path string) (factoryReply, bool) {
	tail, partial := readTranscriptTail(path, factoryTranscriptTailBytes)
	if len(tail) == 0 {
		return factoryReply{}, false
	}
	lines := bytes.Split(tail, []byte("\n"))
	if partial {
		lines = lines[1:]
	}
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		var record struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			Message *struct {
				Role       string          `json:"role"`
				Visibility string          `json:"visibility"`
				Content    json.RawMessage `json:"content"`
			} `json:"message"`
		}
		if json.Unmarshal(line, &record) != nil {
			// A record still being written is the newest line and is not yet a message.
			continue
		}
		if record.Type != "message" || record.Message == nil {
			continue
		}
		if record.Message.Role != "assistant" {
			return factoryReply{}, false
		}
		// A message hidden from one side of the conversation is not the reply: the session sync
		// drops user_only messages and records llm_only ones as errors, and the live path must not
		// call either the turn's answer. Refused rather than skipped, so an earlier message is not
		// promoted in its place.
		if v := record.Message.Visibility; v == "user_only" || v == "llm_only" {
			return factoryReply{}, false
		}
		text, hasToolUse := factoryAssistantText(record.Message.Content)
		if hasToolUse || strings.TrimSpace(text) == "" {
			return factoryReply{}, false
		}
		id := record.ID
		if id == "" {
			sum := sha256.Sum256([]byte(text))
			id = "sha256:" + hex.EncodeToString(sum[:])
		}
		return factoryReply{id: id, text: text}, true
	}
	return factoryReply{}, false
}

// factoryAssistantText joins the text blocks of a Droid message body, which is either a string or
// a list of content blocks, and reports whether any block is a tool call.
func factoryAssistantText(content json.RawMessage) (string, bool) {
	var plain string
	if json.Unmarshal(content, &plain) == nil {
		return plain, false
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(content, &blocks) != nil {
		return "", false
	}
	var parts []string
	hasToolUse := false
	for _, block := range blocks {
		switch block.Type {
		case "text":
			if strings.TrimSpace(block.Text) != "" {
				parts = append(parts, block.Text)
			}
		case "tool_use":
			hasToolUse = true
		}
	}
	return strings.Join(parts, "\n\n"), hasToolUse
}

// readTranscriptTail returns up to the last max bytes of a regular .jsonl file, and whether they
// start mid-file (so the first line is a fragment).
func readTranscriptTail(path string, max int64) ([]byte, bool) {
	path = strings.TrimSpace(path)
	if path == "" || !strings.EqualFold(filepath.Ext(path), ".jsonl") {
		return nil, false
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	size := info.Size()
	window := size
	if window > max {
		window = max
	}
	buf := make([]byte, window)
	if _, err := file.ReadAt(buf, size-window); err != nil && err != io.EOF {
		return nil, false
	}
	return buf, window < size
}

// emitFactoryTranscriptReply records the final reply of a Droid turn read from its transcript, at
// most once per reply: a transcript that has not moved since the previous Stop names the same
// record, and the session state remembers which one was written last.
func emitFactoryTranscriptReply(logger *logging.Logger, input map[string]interface{}, sessionID, transcriptPath string, st *state.SessionState) {
	reply, ok := factoryTranscriptReply(transcriptPath)
	if !ok {
		return
	}
	// A state file that cannot be written costs at most a duplicate, which is better than a lost
	// reply; only a reply the state says was already written is skipped.
	if fresh, err := st.MarkReplyRecorded(reply.id); err == nil && !fresh {
		return
	}
	fields := sessionFields(sessionID, input)
	fields["raw"] = mergeNested(fields["raw"], map[string]interface{}{"factory": map[string]interface{}{"reply_message_id": reply.id, "source": "transcript"}})
	emitAssistantMessage(logger, input, fields, reply.text)
}
