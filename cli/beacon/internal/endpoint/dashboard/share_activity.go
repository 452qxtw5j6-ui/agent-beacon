package dashboard

import (
	"strings"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/schema"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// shareActivity decides which of a session's events count as activity that makes its shared trace
// stale. Besides Beacon's own bookkeeping, a share made from inside the session is followed by
// events about the share itself: the runtime's events for the `beacon share` command (its call and
// its completion, matched by gen_ai.tool.call.id) and the agent's reply about it -- only when the
// session itself holds that share call, in the reply's turn (prompt.id) or, for a runtime without
// turn ids, between its last other activity and the record. Counting those
// would leave a session shared or refreshed from inside itself stale forever. Anything else -- a
// new prompt, another tool call, a file write, a command that is not the share -- still counts.
//
// It is state carried across a session's events in log order, so the trace projection persists it
// with the rest of its running state (traceAggregateState).
type shareActivity struct {
	// ShareCalls are the tool call ids of `beacon share` invocations.
	ShareCalls map[string]bool `json:"share_calls,omitempty"`
	// SharePrompts are the turns (prompt.id) that ran `beacon share`.
	SharePrompts map[string]bool `json:"share_prompts,omitempty"`
	// ShareCallPending is true from a `beacon share` call in this session until the next event
	// that counts: a session.shared record that arrives meanwhile is that call's.
	ShareCallPending bool `json:"share_call_pending,omitempty"`
	// QuietSinceShare is true from a session.shared record that this session's own share call
	// wrote until the next event that counts. A record on its own (a share from another terminal,
	// or --follow) never starts it: the agent's output after such a record was not uploaded.
	QuietSinceShare bool `json:"quiet_since_share,omitempty"`
}

// isBeaconShareCommand reports whether a shell command runs `beacon share` (any subcommand or
// flags): `beacon` must be in command position -- the start of the command or of a segment after
// `;`, `&&`, `||`, `|`, `(` or a newline outside quotes -- optionally after environment assignments,
// `sudo`, `exec` or `env`, and optionally with a path (`/opt/beacon/bin/beacon`, `./beacon`,
// `beacon.exe`), followed by `share`. A mention inside an argument (`rg "beacon share"`,
// `git commit -m 'beacon share ...'`, `echo beacon share`) is not a share call.
func isBeaconShareCommand(command string) bool {
	if command == "" {
		return false
	}
	for _, segment := range shellSegments(command) {
		words := strings.Fields(segment)
		i := 0
		for i < len(words) && (isEnvAssignment(words[i]) || words[i] == "sudo" || words[i] == "exec" || words[i] == "env") {
			i++
		}
		if i+1 < len(words) && isBeaconExecutable(words[i]) && words[i+1] == "share" {
			return true
		}
	}
	return false
}

// shellSegments splits a command at the separators that start a new command (`;`, `&`, `|`, `(`,
// `)`, newline), outside single and double quotes. Quoted text stays inside its segment, so a
// separator in an argument does not start one.
func shellSegments(command string) []string {
	var segments []string
	var current strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if strings.TrimSpace(current.String()) != "" {
			segments = append(segments, current.String())
		}
		current.Reset()
	}
	for _, r := range command {
		switch {
		case escaped:
			escaped = false
			current.WriteRune(r)
		case r == '\\' && quote != '\'':
			escaped = true
			current.WriteRune(r)
		case quote != 0:
			if r == quote {
				quote = 0
			}
			current.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			current.WriteRune(r)
		case r == ';' || r == '&' || r == '|' || r == '(' || r == ')' || r == '\n':
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()
	return segments
}

func isEnvAssignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	for i, r := range name {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// isBeaconExecutable is the word `beacon`, or a path to it, as a command names it.
func isBeaconExecutable(word string) bool {
	word = strings.Trim(word, `"'`)
	if i := strings.LastIndexAny(word, `/\`); i >= 0 {
		word = word[i+1:]
	}
	word = strings.ToLower(word)
	return word == "beacon" || word == "beacon.exe"
}

// counts reports whether event is activity that makes a share stale, and updates the state.
func (s *shareActivity) counts(event schema.Event) bool {
	action := event.Event.Action
	if action == "session.shared" {
		s.QuietSinceShare = s.ShareCallPending
		return false
	}
	if shareBookkeeping(action) {
		return false
	}
	// An event the share projection would not upload (status and idle lifecycle, metrics,
	// token-only telemetry, ...) cannot make the shared trace out of date: a refresh would send
	// nothing for it.
	if !asymptoteobserve.ShareProjects(event) {
		return false
	}
	callID := asymptoteobserve.ToolCallID(&event)
	promptID := asymptoteobserve.PromptID(&event)
	if isShareCallEvent(event) {
		if callID != "" {
			if s.ShareCalls == nil {
				s.ShareCalls = map[string]bool{}
			}
			s.ShareCalls[callID] = true
		}
		if promptID != "" {
			if s.SharePrompts == nil {
				s.SharePrompts = map[string]bool{}
			}
			s.SharePrompts[promptID] = true
		}
		s.ShareCallPending = true
		return false
	}
	if callID != "" && s.ShareCalls[callID] {
		return false // the share call's completion, which may not repeat the command
	}
	if isAssistantOutput(event) {
		if s.QuietSinceShare || (promptID != "" && s.SharePrompts[promptID]) {
			return false
		}
		return true
	}
	s.QuietSinceShare, s.ShareCallPending = false, false
	return true
}

func isShareCallEvent(event schema.Event) bool {
	if event.Command != nil && isBeaconShareCommand(event.Command.Command) {
		return true
	}
	return event.Tool != nil && isBeaconShareCommand(event.Tool.Command)
}

// isAssistantOutput is an event that only carries the agent's own output, what it cost, or the end
// of its turn: no prompt, tool call, command or file activity. Turn ends include Claude Code's Stop
// hook ("Agent response completed": tool.completed with no tool call id and no tool, command or
// file payload) and the plugin runtimes' agent.response / agent.response.completed.
func isAssistantOutput(event schema.Event) bool {
	switch event.Event.Action {
	case "agent.message", "agent.reasoning", "agent.response", "agent.response.completed":
		return true
	case "tool.completed":
		return isPayloadlessTurnEnd(event)
	}
	if event.Command != nil || event.Tool != nil || event.File != nil || event.MCP != nil {
		return false
	}
	if event.Prompt != nil && strings.TrimSpace(event.Prompt.Text) != "" {
		return false
	}
	switch event.Event.Category {
	case "prompt", "tool", "command", "file", "mcp", "approval":
		return false
	}
	return event.GenAI != nil && event.GenAI.Usage != nil
}

// shareRelevantRecord is the part of record that the sharing state reads (noteSharing and
// shareActivity), so the unfiltered sharing pass can hold a session's records until it can fold
// them in append order without holding their content.
func shareRelevantRecord(record EventRecord) EventRecord {
	e := record.Event
	// Timestamp, Sequence and the record's ID are what SortRecordsAppendOrder reads, so the slim
	// records sort exactly as ReadSessionDetail sorts the full ones.
	slim := schema.Event{
		Timestamp: e.Timestamp,
		Sequence:  e.Sequence,
		Event:     e.Event,
		Harness:   e.Harness,
		Session:   e.Session,
		MCP:       e.MCP,
	}
	if e.Event.Action == "session.shared" {
		slim.Raw = e.Raw
	}
	if e.Prompt != nil {
		slim.Prompt = &schema.PromptInfo{ID: e.Prompt.ID}
		if strings.TrimSpace(e.Prompt.Text) != "" {
			slim.Prompt.Text = "-"
		}
	}
	if e.Command != nil {
		slim.Command = &schema.CommandInfo{Command: e.Command.Command}
	}
	if e.Tool != nil {
		tool := *e.Tool
		slim.Tool = &tool
	}
	if e.File != nil {
		slim.File = &schema.FileInfo{Path: e.File.Path}
	}
	if e.GenAI != nil {
		slim.GenAI = &schema.GenAIInfo{Usage: e.GenAI.Usage}
		if id := asymptoteobserve.ToolCallID(&e); id != "" {
			slim.GenAI.Tool = &asymptoteobserve.GenAIToolInfo{Call: &asymptoteobserve.GenAIToolCallInfo{ID: id}}
		}
	}
	return EventRecord{ID: record.ID, Line: record.Line, Event: slim, Parsed: record.Parsed}
}

// isPayloadlessTurnEnd is a completion event that names no tool call: no call id and no tool,
// command, file or MCP payload, which is how a turn-end hook (Claude Code's Stop) records itself.
func isPayloadlessTurnEnd(event schema.Event) bool {
	if asymptoteobserve.ToolCallID(&event) != "" || event.Command != nil || event.File != nil || event.MCP != nil {
		return false
	}
	if event.Tool != nil && (event.Tool.Name != "" || event.Tool.Command != "" || event.Tool.Path != "") {
		return false
	}
	return true
}
