package asymptoteobserve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

// This file is the CLI half of the shared-trace wire contract, beacon.share.v1: the request and
// response bodies `beacon share` exchanges with beacon.sh, and the projection of one session's
// endpoint events into the messages a shared trace is made of.
//
// A shared trace is a snapshot a person chose to publish, so the projection is conservative about
// what leaves the machine: every event goes through SanitizeEvent first, local paths are rewritten
// relative to the session's directory or the home directory, and Beacon's own bookkeeping events
// (heartbeats, metric datapoints, the session.shared record itself) are left out.

// ShareSchemaVersion names the wire contract.
const ShareSchemaVersion = "beacon.share.v1"

// Visibility levels of a shared trace. Direct is the default: anyone with the link.
const (
	ShareVisibilityPublic  = "public"
	ShareVisibilityDirect  = "direct"
	ShareVisibilityPrivate = "private"
)

// ValidShareVisibility reports whether value is one of the three visibility levels.
func ValidShareVisibility(value string) bool {
	switch value {
	case ShareVisibilityPublic, ShareVisibilityDirect, ShareVisibilityPrivate:
		return true
	}
	return false
}

// Message roles.
const (
	ShareRoleUser      = "user"
	ShareRoleAssistant = "assistant"
	ShareRoleSystem    = "system"
)

// Part types.
const (
	SharePartText        = "text"
	SharePartThinking    = "thinking"
	SharePartToolCall    = "tool_call"
	SharePartToolResult  = "tool_result"
	SharePartError       = "error"
	SharePartSystemEvent = "system_event"
)

// Tool kinds, the toolKind of a tool_call part.
const (
	ShareToolKindTerminalCommand = "terminal_command"
	ShareToolKindRead            = "read"
	ShareToolKindEdit            = "edit"
	ShareToolKindWrite           = "write"
	ShareToolKindDelete          = "delete"
	ShareToolKindGrep            = "grep"
	ShareToolKindGlob            = "glob"
	ShareToolKindWebSearch       = "web_search"
	ShareToolKindWebFetch        = "web_fetch"
	ShareToolKindTask            = "task"
	ShareToolKindTodo            = "todo"
	ShareToolKindMCP             = "mcp"
	ShareToolKindOther           = "other"
)

// Tool result statuses.
const (
	ShareStatusSuccess = "success"
	ShareStatusError   = "error"
)

// Relationship types of related_to.
const (
	ShareRelationshipSubagent = "subagent"
	ShareRelationshipResume   = "resume"
)

// ShareSourceCLI is the source the CLI reports for traces it uploads.
const ShareSourceCLI = "cli"

// ShareMaxMessagesPerBatch is the most messages one batch request may carry.
const ShareMaxMessagesPerBatch = 1000

// ShareTitleMaxRunes bounds a title derived from the first prompt.
const ShareTitleMaxRunes = 80

// ShareTokenUsageV1 is a token count in the contract's flat shape. Every field is written, zero
// included, because the contract defines all five.
type ShareTokenUsageV1 struct {
	InputTokens              int64 `json:"input_tokens"`
	OutputTokens             int64 `json:"output_tokens"`
	CacheReadInputTokens     int64 `json:"cache_read_input_tokens"`
	CacheCreationInputTokens int64 `json:"cache_creation_input_tokens"`
	ReasoningOutputTokens    int64 `json:"reasoning_output_tokens"`
}

// IsZero reports whether no count is set.
func (u ShareTokenUsageV1) IsZero() bool {
	return u == ShareTokenUsageV1{}
}

// ShareTraceV1 is the body of PUT /v1/traces/{external_id}: the trace's metadata. There is
// deliberately no local path field; ProjectName is a name, never a directory.
type ShareTraceV1 struct {
	SchemaVersion    string             `json:"schema_version"`
	AgentID          string             `json:"agent_id"`
	Title            string             `json:"title,omitempty"`
	Visibility       string             `json:"visibility,omitempty"`
	Model            string             `json:"model,omitempty"`
	ProjectName      string             `json:"project_name,omitempty"`
	GitRemoteURL     string             `json:"git_remote_url,omitempty"`
	GitBranch        string             `json:"git_branch,omitempty"`
	GitRef           string             `json:"git_ref,omitempty"`
	TokenUsage       *ShareTokenUsageV1 `json:"token_usage,omitempty"`
	CostUSD          *float64           `json:"cost_usd,omitempty"`
	SourceSessionID  string             `json:"source_session_id,omitempty"`
	SourceCreatedAt  string             `json:"source_created_at,omitempty"`
	SourceUpdatedAt  string             `json:"source_updated_at,omitempty"`
	RelatedTo        string             `json:"related_to,omitempty"`
	RelationshipType string             `json:"relationship_type,omitempty"`
	Source           string             `json:"source,omitempty"`
}

// ShareTraceResultV1 is the response of PUT /v1/traces/{external_id}.
type ShareTraceResultV1 struct {
	ID           string `json:"id"`
	ExternalID   string `json:"external_id"`
	URL          string `json:"url"`
	Visibility   string `json:"visibility"`
	MessageCount int    `json:"message_count"`
	Created      bool   `json:"created"`
}

// ShareTraceStateV1 is the owner's view of a trace from GET /v1/traces/{external_id}: enough of
// the trace metadata to report on, and the message watermark a refresh continues from.
type ShareTraceStateV1 struct {
	ID            string             `json:"id"`
	ExternalID    string             `json:"external_id,omitempty"`
	URL           string             `json:"url"`
	Title         string             `json:"title,omitempty"`
	AgentID       string             `json:"agent_id,omitempty"`
	Model         string             `json:"model,omitempty"`
	Visibility    string             `json:"visibility"`
	TokenUsage    *ShareTokenUsageV1 `json:"token_usage,omitempty"`
	MessageCount  int                `json:"message_count"`
	LastMessageID string             `json:"last_message_id,omitempty"`
	MaxOrder      int                `json:"max_order"`
	CreatedAt     string             `json:"created_at,omitempty"`
	UpdatedAt     string             `json:"updated_at,omitempty"`
}

// ShareMessagesBatchV1 is the body of POST /v1/traces/{external_id}/messages/batch.
type ShareMessagesBatchV1 struct {
	Messages []ShareMessageV1 `json:"messages"`
}

// ShareBatchResultV1 is the response of a message batch.
type ShareBatchResultV1 struct {
	Accepted     int `json:"accepted"`
	MessageCount int `json:"message_count"`
}

// ShareMessageV1 is one message of a shared trace. ID is stable across uploads, which is what makes
// re-sending a batch an idempotent upsert.
type ShareMessageV1 struct {
	ID         string             `json:"id"`
	Order      int                `json:"order"`
	Role       string             `json:"role"`
	Timestamp  string             `json:"timestamp"`
	Model      string             `json:"model,omitempty"`
	Text       string             `json:"text"`
	Parts      []SharePartV1      `json:"parts"`
	TokenUsage *ShareTokenUsageV1 `json:"token_usage,omitempty"`
}

// SharePartV1 is one part of a message. Content is one of the Share*Content types below, or a
// map[string]interface{} of small scalars for a system_event.
type SharePartV1 struct {
	Type    string      `json:"type"`
	Order   int         `json:"order"`
	Content interface{} `json:"content"`
}

// ShareTextContent is the content of a text or thinking part.
type ShareTextContent struct {
	Text string `json:"text"`
}

// ShareToolCallContent is the content of a tool_call part. Diff is the edit's retained diff when the
// runtime reported one; it lives on the call because the contract's tool_result has no diff.
type ShareToolCallContent struct {
	CallID   string                 `json:"callId"`
	ToolName string                 `json:"toolName"`
	ToolKind string                 `json:"toolKind"`
	Args     map[string]interface{} `json:"args"`
	Command  string                 `json:"command,omitempty"`
	FilePath string                 `json:"filePath,omitempty"`
	Diff     string                 `json:"diff,omitempty"`
}

// ShareToolResultContent is the content of a tool_result part.
type ShareToolResultContent struct {
	CallID     string `json:"callId"`
	ToolName   string `json:"toolName"`
	Output     string `json:"output"`
	Status     string `json:"status"`
	ExitCode   *int   `json:"exitCode,omitempty"`
	DurationMS *int64 `json:"durationMs,omitempty"`
}

// ShareErrorContent is the content of an error part.
type ShareErrorContent struct {
	Message string `json:"message"`
}

var shareExternalIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$`)

// ValidShareExternalID reports whether id is a well-formed external id.
func ValidShareExternalID(id string) bool {
	return shareExternalIDPattern.MatchString(id)
}

// ShareExternalID is the client-chosen id of a session's shared trace: `<harness>:<session-id>`
// when that is a valid external id, otherwise `<harness>:sha256-<first 32 hex of sha256(session-id)>`.
// The harness is normalized, so every capture path of one session names the same trace.
func ShareExternalID(harness, sessionID string) string {
	name := NormalizeHarnessName(harness)
	if name == "" {
		name = strings.ToLower(strings.TrimSpace(harness))
	}
	if !ValidShareExternalID(name) || strings.Contains(name, ":") {
		name = "unknown"
	}
	if id := name + ":" + sessionID; sessionID != "" && ValidShareExternalID(id) {
		return id
	}
	sum := sha256.Sum256([]byte(sessionID))
	return name + ":sha256-" + hex.EncodeToString(sum[:])[:32]
}

// ShareToolKind classifies a tool for the contract's toolKind, from the tool's own name first --
// every runtime names its tools differently, so the table covers each supported runtime's
// spellings -- and then from what Beacon recorded about the call (an MCP server, a command, a file
// operation). Anything else is "other".
func ShareToolKind(toolName, action, category string, isMCP bool) string {
	name := normalizeToolName(toolName)
	if kind, ok := shareToolKindsByName[name]; ok {
		return kind
	}
	lowerAction := strings.ToLower(strings.TrimSpace(action))
	lowerCategory := strings.ToLower(strings.TrimSpace(category))
	rawLower := strings.ToLower(strings.TrimSpace(toolName))
	switch {
	case isMCP || lowerCategory == "mcp" || strings.HasPrefix(lowerAction, "mcp.") ||
		strings.HasPrefix(rawLower, "mcp__") || strings.HasPrefix(rawLower, "mcp_") || strings.HasPrefix(rawLower, "mcp."):
		return ShareToolKindMCP
	case strings.HasPrefix(lowerAction, "command.") || lowerCategory == "command":
		return ShareToolKindTerminalCommand
	case lowerAction == "file.read":
		return ShareToolKindRead
	case lowerAction == "file.created":
		return ShareToolKindWrite
	case lowerAction == "file.deleted":
		return ShareToolKindDelete
	case lowerAction == "file.modified" || lowerAction == "file.edited":
		return ShareToolKindEdit
	}
	switch {
	case name == "":
		return ShareToolKindOther
	case strings.Contains(name, "bash") || strings.Contains(name, "shell") || strings.Contains(name, "terminal"):
		return ShareToolKindTerminalCommand
	case strings.Contains(name, "websearch"):
		return ShareToolKindWebSearch
	case strings.Contains(name, "webfetch") || strings.Contains(name, "fetchurl"):
		return ShareToolKindWebFetch
	case strings.Contains(name, "todo"):
		return ShareToolKindTodo
	case strings.Contains(name, "grep"):
		return ShareToolKindGrep
	case strings.Contains(name, "glob"):
		return ShareToolKindGlob
	case strings.Contains(name, "read"):
		return ShareToolKindRead
	case strings.Contains(name, "edit") || strings.Contains(name, "patch") || strings.Contains(name, "replace"):
		return ShareToolKindEdit
	case strings.Contains(name, "write") || strings.Contains(name, "create"):
		return ShareToolKindWrite
	case strings.Contains(name, "delete"):
		return ShareToolKindDelete
	}
	return ShareToolKindOther
}

// normalizeToolName lowercases a tool name and drops separators, so exec_command, execCommand and
// exec-command compare equal. A namespace prefix some runtimes add ("functions.", "default_api:")
// is dropped first.
func normalizeToolName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{"functions.", "default_api:", "default_api."} {
		name = strings.TrimPrefix(name, prefix)
	}
	var b strings.Builder
	for _, r := range name {
		if r == '_' || r == '-' || r == ' ' || r == '.' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// shareToolKindsByName maps normalized tool names to kinds: Claude Code, Codex CLI, Cursor, Gemini
// CLI, Qwen Code, OpenCode, Cline, the Pi family, Copilot, Kiro, OpenHands, Antigravity, DeepSeek
// Harness, Grok Build and fx spellings.
var shareToolKindsByName = func() map[string]string {
	table := map[string][]string{
		ShareToolKindTerminalCommand: {
			"bash", "shell", "execcommand", "exec", "localshell", "runterminalcmd", "runterminalcommand",
			"runcommand", "runshellcommand", "executebash", "executecommand", "terminal", "command",
			"bashoutput", "killshell", "killbash", "terminalsend", "ipython", "powershell", "cmd",
		},
		ShareToolKindRead: {
			"read", "view", "readfile", "viewfile", "cat", "notebookread", "readmanyfiles", "openfile",
			"fsread", "readimage",
		},
		ShareToolKindEdit: {
			"edit", "multiedit", "applypatch", "strreplace", "strreplaceeditor", "strreplacebasededittool",
			"searchreplace", "editfile", "replace", "notebookedit", "patch", "replaceinfile", "editnotebook",
			"fswrite",
		},
		ShareToolKindWrite: {
			"write", "create", "writefile", "createfile", "writetofile", "newfile",
		},
		ShareToolKindDelete: {
			"delete", "deletefile", "remove", "removefile", "rm",
		},
		ShareToolKindGrep: {
			"grep", "grepsearch", "search", "rg", "ripgrep", "searchfilecontent", "codebasesearch",
			"searchfiles",
		},
		ShareToolKindGlob: {
			"glob", "find", "filesearch", "findbyname", "ls", "listdir", "listdirectory", "listfiles",
		},
		ShareToolKindWebSearch: {
			"websearch", "googlesearch", "googlewebsearch", "searchweb",
		},
		ShareToolKindWebFetch: {
			"webfetch", "fetch", "fetchurl", "readurl", "urlfetch", "browse",
		},
		ShareToolKindTask: {
			"task", "agent", "subagent", "spawnagent", "dispatchagent", "delegate", "newtask", "runsubagent",
		},
		ShareToolKindTodo: {
			"todowrite", "todoread", "todo", "updateplan", "writetodos", "updatetodos", "todolist",
		},
	}
	out := map[string]string{}
	for kind, names := range table {
		for _, name := range names {
			out[name] = kind
		}
	}
	return out
}()

// ShareOptions tunes the projection. The zero value is what BuildShareMessages uses: the working
// directory comes from the events and the home directory from the environment.
type ShareOptions struct {
	// WorkingDirectory is the session's directory. Paths under it are written relative to it.
	WorkingDirectory string
	// HomeDirectory is replaced by "~" in paths outside the working directory.
	HomeDirectory string
	// NoHomeLookup leaves HomeDirectory empty rather than reading it from the environment.
	NoHomeLookup bool
}

// BuildShareMessages projects one session's events into shared-trace messages.
//
// Events are sanitized (SanitizeEvent), ordered by timestamp with the event id as tie-breaker, and
// mapped as follows:
//
//   - a prompt is a user message with a text part;
//   - assistant text and reasoning are assistant messages with a text or thinking part;
//   - a tool invocation is an assistant message with a tool_call part, and its completion is a
//     separate message with a tool_result part carrying the same callId. Hook runtimes report one
//     call twice (before and after); the two are paired by gen_ai.tool.call.id, or, when the
//     runtime names no call id, by tool name with the most recent unanswered invocation. A call or
//     result reported twice (a hook and an OTLP copy of one action) is written once, with the
//     second copy only filling fields the first lacked. A completion with no invocation gets a
//     tool_call message of its own just before it, so every result has a call;
//   - approvals, policy decisions and session lifecycle are system messages with a system_event
//     part; failures that are not a tool's are system messages with an error part.
//
// Heartbeats, inventory, metric datapoints and the session.shared record are not messages.
func BuildShareMessages(events []Event) []ShareMessageV1 {
	return BuildShareMessagesWithOptions(events, ShareOptions{})
}

// BuildShareMessagesWithOptions is BuildShareMessages with explicit options.
func BuildShareMessagesWithOptions(events []Event, opts ShareOptions) []ShareMessageV1 {
	if opts.WorkingDirectory == "" {
		for _, event := range events {
			if event.Session != nil && strings.TrimSpace(event.Session.WorkingDirectory) != "" {
				opts.WorkingDirectory = strings.TrimSpace(event.Session.WorkingDirectory)
				break
			}
		}
	}
	if opts.HomeDirectory == "" && !opts.NoHomeLookup {
		if home, err := os.UserHomeDir(); err == nil {
			opts.HomeDirectory = home
		}
	}
	b := &shareBuilder{
		scrub:       newPathScrubber(opts.WorkingDirectory, opts.HomeDirectory),
		seen:        map[string]bool{},
		calls:       map[string]*ShareToolCallContent{},
		results:     map[string]*ShareToolResultContent{},
		callMessage: map[string]*ShareMessageV1{},
	}
	for _, item := range orderShareEvents(events) {
		b.add(item)
	}
	out := make([]ShareMessageV1, 0, len(b.messages))
	for i, message := range b.messages {
		message.Order = i + 1
		out = append(out, *message)
	}
	return out
}

type shareEvent struct {
	event Event
	id    string
	ts    time.Time
	hasTS bool
	rank  int
}

// orderShareEvents sanitizes events, gives each its message id, and sorts them by timestamp, then
// with invocations ahead of everything else at one instant (a pre-tool and a post-tool hook can
// share a timestamp), then by id. Events that cannot be timed keep their input position relative
// to each other, after every timed event.
func orderShareEvents(events []Event) []shareEvent {
	items := make([]shareEvent, 0, len(events))
	for _, event := range events {
		id := ShareMessageID(event)
		event = SanitizeEvent(event, 1<<30)
		item := shareEvent{event: event, id: id}
		if ts, err := ParseTimestamp(event.Timestamp); err == nil {
			item.ts, item.hasTS = ts, true
		} else if ts, err := time.Parse(time.RFC3339Nano, event.Timestamp); err == nil {
			item.ts, item.hasTS = ts, true
		}
		if isShareInvocation(event) {
			item.rank = 0
		} else {
			item.rank = 1
		}
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.hasTS != b.hasTS {
			return a.hasTS
		}
		if !a.hasTS {
			return false
		}
		if !a.ts.Equal(b.ts) {
			return a.ts.Before(b.ts)
		}
		if a.rank != b.rank {
			return a.rank < b.rank
		}
		return a.id < b.id
	})
	return items
}

// ShareMessageID is the stable id of the message an event becomes: its event.id when it has one,
// otherwise the id the runtime log writer would derive for it (EventIDForLine over the event as the
// writer stamps it), so a session read from its runtime's store names its messages the same way on
// every upload.
func ShareMessageID(event Event) string {
	if id := strings.TrimSpace(event.Event.ID); id != "" {
		return id
	}
	event.Event.ID = ""
	AttachDerivedTrace(&event)
	event = SanitizeEvent(event, 64*1024)
	data, err := json.Marshal(event)
	if err != nil {
		return eventUUID("share", event.Timestamp+"\x00"+event.Event.Action+"\x00"+event.Message)
	}
	return EventIDForLine(data)
}

type shareBuilder struct {
	scrub    pathScrubber
	messages []*ShareMessageV1
	seen     map[string]bool
	// calls, results and callMessage are keyed by callId.
	calls       map[string]*ShareToolCallContent
	results     map[string]*ShareToolResultContent
	callMessage map[string]*ShareMessageV1
	// pending holds call ids of invocations that named no runtime call id, newest last, waiting for
	// a completion to pair with by tool name.
	pending []string
}

type shareEventClass int

const (
	shareSkip shareEventClass = iota
	sharePrompt
	shareAgentText
	shareThinking
	shareTool
	shareApproval
	shareSystem
	shareError
)

func classifyShareEvent(event Event) shareEventClass {
	action := strings.ToLower(strings.TrimSpace(event.Event.Action))
	category := strings.ToLower(strings.TrimSpace(event.Event.Category))
	switch {
	case action == "" || action == "session.shared":
		return shareSkip
	case category == "metric" || category == "inventory" || category == "health" || category == "telemetry" ||
		strings.HasPrefix(action, "endpoint.") || strings.HasPrefix(action, "telemetry.") ||
		strings.HasPrefix(action, "inventory.") || strings.HasPrefix(action, "token.") ||
		strings.HasPrefix(action, "destination.") || strings.HasPrefix(action, "health."):
		return shareSkip
	case action == "session.activity" || action == "session.idle" || action == "session.status" ||
		action == "session.lock" || action == "mcp.tool_listed" || action == "agent.detected":
		return shareSkip
	case category == "prompt" || strings.HasPrefix(action, "prompt."):
		return sharePrompt
	case strings.Contains(action, "reasoning") || strings.Contains(action, "thinking"):
		return shareThinking
	case action == "agent.message" || action == "assistant.message" || action == "agent.response" ||
		action == "agent.response.completed" || action == "agent.plan":
		return shareAgentText
	case category == "approval" || strings.HasPrefix(action, "approval.") || strings.HasPrefix(action, "policy."):
		return shareApproval
	case strings.HasPrefix(action, "tool.") || strings.HasPrefix(action, "command.") ||
		strings.HasPrefix(action, "file.") || action == "mcp.tool_invoked" || action == "mcp.tool_call" ||
		category == "tool" || category == "command" || category == "file":
		return shareTool
	case action == "session.error" || action == "agent.error" || strings.HasPrefix(action, "error.") ||
		category == "error":
		return shareError
	}
	return shareSystem
}

// isShareInvocation reports an event that names a tool call before it runs.
func isShareInvocation(event Event) bool {
	switch strings.ToLower(strings.TrimSpace(event.Event.Action)) {
	case "tool.invoked", "tool.started", "tool.call", "tool.execute.before", "tool.execution_start",
		"command.invoked", "command.execute.before", "mcp.tool_call":
		return true
	}
	return false
}

// isShareCompletion reports an event that says a tool call finished: its action says so, or it
// carries what only a finished call has (a result, output, an exit code, a diff, an error).
func isShareCompletion(event Event) bool {
	switch strings.ToLower(strings.TrimSpace(event.Event.Action)) {
	case "tool.completed", "tool.failed", "tool.execute.after", "tool.execution_complete", "tool.result":
		return true
	}
	if event.GenAI != nil && event.GenAI.Tool != nil && event.GenAI.Tool.Call != nil && event.GenAI.Tool.Call.Result != nil {
		return true
	}
	if event.Command != nil && (event.Command.Output != "" || event.Command.ExitCode != nil || event.Command.DurationMS > 0) {
		return true
	}
	if event.File != nil && event.File.Diff != "" {
		return true
	}
	return event.Error != nil && event.Error.Type != ""
}

func (b *shareBuilder) add(item shareEvent) {
	if b.seen[item.id] {
		return
	}
	event := item.event
	class := classifyShareEvent(event)
	if class == shareSkip {
		return
	}
	b.seen[item.id] = true
	switch class {
	case sharePrompt:
		text := sharePromptText(event)
		if text == "" {
			text = "(prompt text not retained)"
		}
		b.appendText(item, ShareRoleUser, SharePartText, text)
	case shareAgentText:
		text := shareAssistantText(event, GenAIPartTypeText)
		if text == "" {
			return
		}
		b.appendText(item, ShareRoleAssistant, SharePartText, text)
	case shareThinking:
		text := shareAssistantText(event, GenAIPartTypeReasoning)
		if text == "" {
			return
		}
		b.appendText(item, ShareRoleAssistant, SharePartThinking, text)
	case shareTool:
		b.addTool(item)
	case shareApproval:
		b.addApproval(item)
	case shareError:
		msg := b.scrub.text(firstNonEmptyString(event.Message, errorType(event), event.Event.Action))
		b.append(item, ShareRoleSystem, msg, SharePartV1{Type: SharePartError, Content: ShareErrorContent{Message: msg}})
	default:
		b.addSystem(item)
	}
}

func (b *shareBuilder) newMessage(item shareEvent, id, role, text string, parts ...SharePartV1) *ShareMessageV1 {
	for i := range parts {
		parts[i].Order = i + 1
	}
	message := &ShareMessageV1{
		ID:        id,
		Role:      role,
		Timestamp: shareTimestamp(item),
		Model:     shareModel(item.event),
		Text:      text,
		Parts:     parts,
	}
	if usage := shareUsage(item.event); usage != nil {
		message.TokenUsage = usage
	}
	return message
}

func (b *shareBuilder) append(item shareEvent, role, text string, parts ...SharePartV1) *ShareMessageV1 {
	message := b.newMessage(item, item.id, role, text, parts...)
	b.messages = append(b.messages, message)
	return message
}

func (b *shareBuilder) appendText(item shareEvent, role, partType, text string) {
	text = b.scrub.text(text)
	b.append(item, role, text, SharePartV1{Type: partType, Content: ShareTextContent{Text: text}})
}

func (b *shareBuilder) addTool(item shareEvent) {
	event := item.event
	callID := ToolCallID(&event)
	toolName := shareToolName(event)
	invocation := isShareInvocation(event)
	completion := !invocation && isShareCompletion(event)

	if !invocation && !completion {
		// Neither phase is explicit (a file read a hook observed, an MCP call a transcript recorded).
		// It completes a call already on the trace, and is a call of its own otherwise.
		if callID != "" && b.calls[callID] != nil {
			completion = true
		} else if callID == "" {
			if paired := b.pairPending(event, toolName); paired != "" {
				callID = paired
				completion = true
			}
		}
		if !completion {
			invocation = true
		}
	}

	if invocation {
		if callID != "" && b.calls[callID] != nil {
			mergeToolCall(b.calls[callID], b.toolCallContent(event, callID, toolName))
			return
		}
		named := callID != ""
		if !named {
			callID = item.id
		}
		call := b.toolCallContent(event, callID, toolName)
		message := b.append(item, ShareRoleAssistant, shareToolCallText(call), SharePartV1{Type: SharePartToolCall, Content: call})
		b.calls[callID] = call
		b.callMessage[callID] = message
		if !named {
			b.pending = append(b.pending, callID)
		}
		return
	}

	// A completion.
	if callID == "" {
		callID = b.pairPending(event, toolName)
	}
	if callID != "" && b.results[callID] != nil {
		mergeToolResult(b.results[callID], b.toolResultContent(event, callID, toolName))
		if call := b.calls[callID]; call != nil {
			mergeToolCall(call, b.toolCallContent(event, callID, toolName))
		}
		return
	}
	if callID == "" || b.calls[callID] == nil {
		// No invocation on the trace: the runtime reported only the finished call (a poll backfill,
		// a post-tool hook alone). Write the call just ahead of its result.
		if callID == "" {
			callID = item.id
		}
		call := b.toolCallContent(event, callID, toolName)
		message := b.newMessage(item, eventUUID("share-call", item.id), ShareRoleAssistant, shareToolCallText(call), SharePartV1{Type: SharePartToolCall, Content: call})
		message.TokenUsage = nil
		b.messages = append(b.messages, message)
		b.calls[callID] = call
		b.callMessage[callID] = message
	} else {
		// The completion often carries what the invocation did not: the diff, the command line.
		mergeToolCall(b.calls[callID], b.toolCallContent(event, callID, toolName))
	}
	if toolName == "" {
		toolName = b.calls[callID].ToolName
	}
	result := b.toolResultContent(event, callID, toolName)
	b.append(item, ShareRoleAssistant, shareToolResultText(result), SharePartV1{Type: SharePartToolResult, Content: result})
	b.results[callID] = result
}

// pairPending finds the most recent unanswered invocation without a runtime call id for the same
// tool, removes it from the queue and returns its call id.
func (b *shareBuilder) pairPending(event Event, toolName string) string {
	command, path := shareCommand(event), shareFilePath(event)
	for i := len(b.pending) - 1; i >= 0; i-- {
		id := b.pending[i]
		call := b.calls[id]
		if call == nil || b.results[id] != nil {
			continue
		}
		if normalizeToolName(call.ToolName) != normalizeToolName(toolName) {
			continue
		}
		if command != "" && call.Command != "" && b.scrub.text(command) != call.Command {
			continue
		}
		if path != "" && call.FilePath != "" && b.scrub.path(path) != call.FilePath {
			continue
		}
		b.pending = append(b.pending[:i], b.pending[i+1:]...)
		return id
	}
	return ""
}

func (b *shareBuilder) toolCallContent(event Event, callID, toolName string) *ShareToolCallContent {
	call := &ShareToolCallContent{
		CallID:   callID,
		ToolName: toolName,
		ToolKind: ShareToolKind(toolName, event.Event.Action, event.Event.Category, event.MCP != nil),
		Args:     b.scrub.args(shareToolArgs(event)),
		Command:  b.scrub.text(shareCommand(event)),
		FilePath: b.scrub.path(shareFilePath(event)),
	}
	if event.File != nil {
		call.Diff = b.scrub.text(event.File.Diff)
	}
	if call.Args == nil {
		call.Args = map[string]interface{}{}
	}
	return call
}

func (b *shareBuilder) toolResultContent(event Event, callID, toolName string) *ShareToolResultContent {
	result := &ShareToolResultContent{
		CallID:   callID,
		ToolName: toolName,
		Output:   b.scrub.text(shareToolOutput(event)),
		Status:   ShareStatusSuccess,
	}
	if event.Command != nil {
		if event.Command.ExitCode != nil {
			code := *event.Command.ExitCode
			result.ExitCode = &code
		}
		if event.Command.DurationMS > 0 {
			ms := event.Command.DurationMS
			result.DurationMS = &ms
		}
	}
	if shareFailed(event) {
		result.Status = ShareStatusError
	}
	return result
}

func mergeToolCall(dst, src *ShareToolCallContent) {
	if dst.ToolName == "" {
		dst.ToolName = src.ToolName
	}
	if dst.ToolKind == "" || dst.ToolKind == ShareToolKindOther {
		dst.ToolKind = src.ToolKind
	}
	if len(dst.Args) == 0 && len(src.Args) > 0 {
		dst.Args = src.Args
	}
	if dst.Command == "" {
		dst.Command = src.Command
	}
	if dst.FilePath == "" {
		dst.FilePath = src.FilePath
	}
	if dst.Diff == "" {
		dst.Diff = src.Diff
	}
}

func mergeToolResult(dst, src *ShareToolResultContent) {
	if dst.ToolName == "" {
		dst.ToolName = src.ToolName
	}
	if dst.Output == "" {
		dst.Output = src.Output
	}
	if dst.ExitCode == nil {
		dst.ExitCode = src.ExitCode
	}
	if dst.DurationMS == nil {
		dst.DurationMS = src.DurationMS
	}
	if src.Status == ShareStatusError {
		dst.Status = ShareStatusError
	}
}

func (b *shareBuilder) addApproval(item shareEvent) {
	event := item.event
	content := map[string]interface{}{}
	action := strings.ToLower(event.Event.Action)
	subtype := "approval"
	if strings.HasPrefix(action, "policy.") || (event.Policy != nil && event.Approval == nil) {
		subtype = "policy"
	}
	content["subtype"] = subtype
	content["action"] = event.Event.Action
	if event.Approval != nil {
		putString(content, "decision", event.Approval.Decision)
		putString(content, "reason", b.scrub.text(event.Approval.Reason))
		if event.Approval.Required {
			content["required"] = true
		}
	}
	if event.Policy != nil {
		putString(content, "policyDecision", event.Policy.Decision)
		putString(content, "enforcement", event.Policy.Enforcement)
		putString(content, "policyName", event.Policy.Name)
		if _, ok := content["reason"]; !ok {
			putString(content, "reason", b.scrub.text(event.Policy.Reason))
		}
	}
	putString(content, "toolName", shareToolName(event))
	putString(content, "callId", ToolCallID(&event))
	putString(content, "command", b.scrub.text(shareCommand(event)))
	putString(content, "fidelity", event.Event.Fidelity)
	text := strings.TrimSpace(strings.Join(nonEmpty(event.Event.Action, stringField(content, "toolName"), stringField(content, "decision")), " "))
	b.append(item, ShareRoleSystem, text, SharePartV1{Type: SharePartSystemEvent, Content: content})
}

func (b *shareBuilder) addSystem(item shareEvent) {
	event := item.event
	content := map[string]interface{}{"subtype": event.Event.Action}
	if event.Handoff != nil {
		putString(content, "sourceHarness", event.Handoff.SourceHarness)
		putString(content, "sourceSessionId", event.Handoff.SourceSessionID)
	}
	if event.VCS != nil && event.VCS.Ref != nil && event.VCS.Ref.Head != nil {
		putString(content, "commit", event.VCS.Ref.Head.Revision)
		putString(content, "branch", event.VCS.Ref.Head.Name)
	}
	if event.SystemContext != nil {
		putString(content, "contextKind", event.SystemContext.Kind)
	}
	putString(content, "fidelity", event.Event.Fidelity)
	summary := b.scrub.text(TruncateString(strings.TrimSpace(event.Message), 500))
	putString(content, "summary", summary)
	b.append(item, ShareRoleSystem, firstNonEmptyString(summary, event.Event.Action), SharePartV1{Type: SharePartSystemEvent, Content: content})
}

func sharePromptText(event Event) string {
	if event.Prompt != nil && strings.TrimSpace(event.Prompt.Text) != "" {
		return strings.TrimSpace(event.Prompt.Text)
	}
	if event.GenAI != nil && event.GenAI.Input != nil {
		if parts := GenAIText(event.GenAI.Input.Messages, RoleUser, GenAIPartTypeText); len(parts) > 0 {
			return boundShareText(strings.Join(parts, "\n\n"))
		}
	}
	return ""
}

// shareAssistantText reads retained assistant text of partType from gen_ai.output.messages. The
// event message is used only when it is not one of the fixed labels writers put there.
func shareAssistantText(event Event, partType string) string {
	if event.GenAI != nil && event.GenAI.Output != nil {
		if parts := GenAIText(event.GenAI.Output.Messages, RoleAssistant, partType); len(parts) > 0 {
			return boundShareText(strings.Join(parts, "\n\n"))
		}
	}
	if event.Content != nil && event.Content.Included && strings.TrimSpace(event.Message) != "" && !looksLikeLabel(event.Message) {
		return strings.TrimSpace(event.Message)
	}
	return ""
}

// looksLikeLabel recognizes the fixed descriptions writers put in event.message ("Codex assistant
// message", "Claude Code reasoning observed"), which are not what the assistant said.
func looksLikeLabel(message string) bool {
	lower := strings.ToLower(strings.TrimSpace(message))
	for _, suffix := range []string{" observed", " message", " reasoning", " response", " completed"} {
		if strings.HasSuffix(lower, suffix) && utf8.RuneCountInString(lower) < 60 {
			return true
		}
	}
	return false
}

// boundShareText holds text joined from several stored parts to the limit one part is stored at,
// and redacts it again, as the dashboard does for the same joined text.
func boundShareText(text string) string {
	return RedactString(TruncateString(text, DefaultStringLimit))
}

func shareToolName(event Event) string {
	if event.Tool != nil && strings.TrimSpace(event.Tool.Name) != "" {
		return strings.TrimSpace(event.Tool.Name)
	}
	if event.GenAI != nil && event.GenAI.Tool != nil && strings.TrimSpace(event.GenAI.Tool.Name) != "" {
		return strings.TrimSpace(event.GenAI.Tool.Name)
	}
	if event.MCP != nil && strings.TrimSpace(event.MCP.Tool) != "" {
		if event.MCP.Server != "" {
			return "mcp__" + event.MCP.Server + "__" + event.MCP.Tool
		}
		return event.MCP.Tool
	}
	switch {
	case event.Command != nil && event.Command.Command != "":
		return "shell"
	case event.File != nil:
		switch strings.ToLower(event.Event.Action) {
		case "file.read":
			return "read"
		case "file.created":
			return "write"
		case "file.deleted":
			return "delete"
		default:
			return "edit"
		}
	}
	return ""
}

func shareCommand(event Event) string {
	if event.Command != nil && strings.TrimSpace(event.Command.Command) != "" {
		return strings.TrimSpace(event.Command.Command)
	}
	if event.Tool != nil {
		return strings.TrimSpace(event.Tool.Command)
	}
	return ""
}

func shareFilePath(event Event) string {
	if event.File != nil && strings.TrimSpace(event.File.Path) != "" {
		return strings.TrimSpace(event.File.Path)
	}
	if event.Tool != nil {
		return strings.TrimSpace(event.Tool.Path)
	}
	return ""
}

// shareToolArgs returns the call's arguments: gen_ai.tool.call.arguments when it is an object (or
// a JSON object in a string), otherwise the tool input a hook kept in raw.
func shareToolArgs(event Event) map[string]interface{} {
	if event.GenAI != nil && event.GenAI.Tool != nil && event.GenAI.Tool.Call != nil {
		if args := objectValue(event.GenAI.Tool.Call.Arguments); args != nil {
			return args
		}
	}
	for _, key := range []string{"tool_input", "toolInput", "arguments", "args", "input"} {
		if args := objectValue(event.Raw[key]); args != nil {
			return args
		}
	}
	return nil
}

func objectValue(value interface{}) map[string]interface{} {
	switch typed := value.(type) {
	case map[string]interface{}:
		if len(typed) == 0 {
			return nil
		}
		return typed
	case string:
		trimmed := strings.TrimSpace(typed)
		if !strings.HasPrefix(trimmed, "{") {
			return nil
		}
		var out map[string]interface{}
		if json.Unmarshal([]byte(trimmed), &out) == nil && len(out) > 0 {
			return SanitizeMap(out, PrivacyOptions{RedactSecrets: true, StringLimit: DefaultRawStringLimit})
		}
	case nil:
		return nil
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			return nil
		}
		var out map[string]interface{}
		if json.Unmarshal(data, &out) == nil && len(out) > 0 {
			return out
		}
	}
	return nil
}

func shareToolOutput(event Event) string {
	if event.Command != nil && strings.TrimSpace(event.Command.Output) != "" {
		return event.Command.Output
	}
	if event.GenAI != nil && event.GenAI.Tool != nil && event.GenAI.Tool.Call != nil && event.GenAI.Tool.Call.Result != nil {
		return boundShareText(ToolResultPlainText(event.GenAI.Tool.Call.Result))
	}
	return ""
}

func shareFailed(event Event) bool {
	action := strings.ToLower(event.Event.Action)
	if strings.Contains(action, "fail") || strings.Contains(action, "error") || strings.Contains(action, "denied") {
		return true
	}
	if event.Error != nil && event.Error.Type != "" {
		return true
	}
	return event.Command != nil && event.Command.ExitCode != nil && *event.Command.ExitCode != 0
}

func errorType(event Event) string {
	if event.Error != nil {
		return event.Error.Type
	}
	return ""
}

func shareToolCallText(call *ShareToolCallContent) string {
	detail := firstNonEmptyString(call.Command, call.FilePath)
	if detail == "" {
		return call.ToolName
	}
	if call.ToolName == "" {
		return TruncateString(detail, 1024)
	}
	return TruncateString(call.ToolName+": "+detail, 1024)
}

func shareToolResultText(result *ShareToolResultContent) string {
	if result.Output != "" {
		return TruncateString(result.Output, 1024)
	}
	return strings.TrimSpace(result.ToolName + " " + result.Status)
}

func shareTimestamp(item shareEvent) string {
	if item.hasTS {
		return item.ts.UTC().Format(time.RFC3339Nano)
	}
	return item.event.Timestamp
}

func shareModel(event Event) string {
	model := event.Model
	if model == "" && event.GenAI != nil {
		if event.GenAI.Response != nil && event.GenAI.Response.Model != "" {
			model = event.GenAI.Response.Model
		} else if event.GenAI.Request != nil {
			model = event.GenAI.Request.Model
		}
	}
	return NormalizeModelName(model)
}

func shareUsage(event Event) *ShareTokenUsageV1 {
	if event.GenAI == nil || event.GenAI.Usage == nil {
		return nil
	}
	usage := ShareTokenUsageFromGenAI(event.GenAI.Usage)
	if usage.IsZero() {
		return nil
	}
	return &usage
}

// ShareTokenUsageFromGenAI flattens one gen_ai.usage block. The one-hour cache-write subset is a
// breakdown of cache_creation and has no field of its own in the contract.
func ShareTokenUsageFromGenAI(usage *GenAIUsageInfo) ShareTokenUsageV1 {
	var out ShareTokenUsageV1
	if usage == nil {
		return out
	}
	if usage.InputTokens != nil {
		out.InputTokens = *usage.InputTokens
	}
	if usage.OutputTokens != nil {
		out.OutputTokens = *usage.OutputTokens
	}
	if usage.CacheRead != nil && usage.CacheRead.InputTokens != nil {
		out.CacheReadInputTokens = *usage.CacheRead.InputTokens
	}
	if usage.CacheCreation != nil && usage.CacheCreation.InputTokens != nil {
		out.CacheCreationInputTokens = *usage.CacheCreation.InputTokens
	}
	if usage.Reasoning != nil && usage.Reasoning.OutputTokens != nil {
		out.ReasoningOutputTokens = *usage.Reasoning.OutputTokens
	}
	return out
}

func putString(m map[string]interface{}, key, value string) {
	if value = strings.TrimSpace(value); value != "" {
		m[key] = value
	}
}

func stringField(m map[string]interface{}, key string) string {
	value, _ := m[key].(string)
	return value
}

func nonEmpty(values ...string) []string {
	out := values[:0:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			out = append(out, value)
		}
	}
	return out
}

// pathScrubber rewrites local paths before they leave the machine: the session's directory
// becomes ".", the home directory "~". A shared trace has no use for the absolute layout of the
// sharer's disk, and the home directory names the local account.
type pathScrubber struct {
	work string
	home string
}

func newPathScrubber(work, home string) pathScrubber {
	clean := func(p string) string {
		p = strings.TrimRight(strings.TrimSpace(p), `/\`)
		// A root or a single short segment would rewrite unrelated text.
		if len(p) < 3 {
			return ""
		}
		return p
	}
	return pathScrubber{work: clean(work), home: clean(home)}
}

func (s pathScrubber) path(p string) string {
	if p == "" {
		return ""
	}
	if s.work != "" {
		if p == s.work {
			return "."
		}
		for _, sep := range []string{"/", `\`} {
			if strings.HasPrefix(p, s.work+sep) {
				return strings.TrimPrefix(p, s.work+sep)
			}
		}
	}
	return s.text(p)
}

func (s pathScrubber) text(value string) string {
	if value == "" {
		return ""
	}
	if s.work != "" {
		value = replacePathPrefix(value, s.work, ".")
	}
	if s.home != "" {
		value = replacePathPrefix(value, s.home, "~")
	}
	return value
}

// replacePathPrefix replaces prefix with repl only where prefix is a whole path: the character
// before it cannot continue a path, and the one after it ends the path or starts its next
// segment. A bare substring match would turn /home/alex into ~ex for a home of /home/al.
func replacePathPrefix(value, prefix, repl string) string {
	if prefix == "" || !strings.Contains(value, prefix) {
		return value
	}
	var b strings.Builder
	rest := value
	for {
		i := strings.Index(rest, prefix)
		if i < 0 {
			b.WriteString(rest)
			return b.String()
		}
		end := i + len(prefix)
		consumed := len(value) - len(rest)
		before := consumed + i
		if (before == 0 || !continuesPath(value[before-1], true)) &&
			(end == len(rest) || !continuesPath(rest[end], false) || endsSentence(rest[end:])) {
			b.WriteString(rest[:i])
			b.WriteString(repl)
		} else {
			b.WriteString(rest[:end])
		}
		rest = rest[end:]
	}
}

// endsSentence reports whether tail is punctuation closing the sentence a path ends, such as
// the "." in "saved to /home/al.", rather than a longer name such as /home/al.bak.
func endsSentence(tail string) bool {
	if tail == "" || (tail[0] != '.' && tail[0] != '-' && tail[0] != '~') {
		return false
	}
	return len(tail) == 1 || !continuesPath(tail[1], false)
}

// continuesPath reports whether c would make a match part of a longer path. Before a match a
// separator also counts, because /srv/home/al is not /home/al; after it a separator starts the
// next segment of the same path.
func continuesPath(c byte, before bool) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '.', c == '_', c == '-', c == '~':
		return true
	case c == '/', c == '\\':
		return before
	}
	return false
}

func (s pathScrubber) args(args map[string]interface{}) map[string]interface{} {
	if args == nil {
		return nil
	}
	out := make(map[string]interface{}, len(args))
	for key, value := range args {
		out[key] = s.value(value)
	}
	return out
}

func (s pathScrubber) value(value interface{}) interface{} {
	switch typed := value.(type) {
	case string:
		return s.text(typed)
	case map[string]interface{}:
		return s.args(typed)
	case []interface{}:
		out := make([]interface{}, len(typed))
		for i, item := range typed {
			out[i] = s.value(item)
		}
		return out
	}
	return value
}

// ShareMetadataFromEvents derives a trace's metadata from its events: the agent, a title from the
// first prompt, the model used most, repository context, summed token usage and runtime-reported
// cost, and the source session's first and last timestamps. Visibility is left for the caller.
//
// Token usage here is a plain sum of every event's gen_ai.usage. That is right for span and
// per-request usage and wrong for cumulative metric series and for a session captured both live
// and by a poll backfill; a caller with the CLI's token aggregator (cli/beacon/internal/tokens,
// which resolves both) should replace TokenUsage and CostUSD with its totals.
func ShareMetadataFromEvents(events []Event) ShareTraceV1 {
	return ShareMetadataFromEventsWithOptions(events, ShareOptions{})
}

// ShareMetadataFromEventsWithOptions is ShareMetadataFromEvents with the path options the title is
// scrubbed with.
func ShareMetadataFromEventsWithOptions(events []Event, opts ShareOptions) ShareTraceV1 {
	meta := ShareTraceV1{SchemaVersion: ShareSchemaVersion, Source: ShareSourceCLI}
	items := orderShareEvents(events)
	models := map[string]int{}
	var modelOrder []string
	var usage ShareTokenUsageV1
	var cost float64
	var hasCost bool
	var workDir, firstPrompt string
	seen := map[string]bool{}
	for _, item := range items {
		event := item.event
		if strings.EqualFold(event.Event.Action, "session.shared") {
			continue
		}
		if meta.AgentID == "" {
			meta.AgentID = NormalizeHarnessName(event.Harness.Name)
		}
		if meta.SourceSessionID == "" && event.Session != nil {
			meta.SourceSessionID = strings.TrimSpace(event.Session.ID)
		}
		if workDir == "" && event.Session != nil {
			workDir = strings.TrimSpace(event.Session.WorkingDirectory)
		}
		if item.hasTS {
			ts := item.ts.UTC().Format(time.RFC3339Nano)
			if meta.SourceCreatedAt == "" {
				meta.SourceCreatedAt = ts
			}
			meta.SourceUpdatedAt = ts
		}
		if firstPrompt == "" && classifyShareEvent(event) == sharePrompt {
			firstPrompt = sharePromptText(event)
		}
		if model := shareModel(event); model != "" {
			if models[model] == 0 {
				modelOrder = append(modelOrder, model)
			}
			models[model]++
		}
		if !seen[item.id] && event.GenAI != nil && event.GenAI.Usage != nil {
			seen[item.id] = true
			u := ShareTokenUsageFromGenAI(event.GenAI.Usage)
			usage.InputTokens += u.InputTokens
			usage.OutputTokens += u.OutputTokens
			usage.CacheReadInputTokens += u.CacheReadInputTokens
			usage.CacheCreationInputTokens += u.CacheCreationInputTokens
			usage.ReasoningOutputTokens += u.ReasoningOutputTokens
			if event.GenAI.Usage.CostUSD != nil {
				cost += *event.GenAI.Usage.CostUSD
				hasCost = true
			}
		}
		if event.VCS != nil {
			if event.VCS.Repository != nil && event.VCS.Repository.URL != nil && meta.GitRemoteURL == "" {
				meta.GitRemoteURL = ShareRemoteURL(event.VCS.Repository.URL.Full)
			}
			if event.VCS.Ref != nil && event.VCS.Ref.Head != nil {
				if ShareBranch(event.VCS.Ref.Head.Name) != "" && meta.GitBranch == "" {
					meta.GitBranch = ShareBranch(event.VCS.Ref.Head.Name)
				}
				// The newest commit wins: a session that made several is described by the last.
				if event.VCS.Ref.Head.Revision != "" {
					meta.GitRef = event.VCS.Ref.Head.Revision
				}
			}
		}
		if event.Run != nil {
			if meta.GitRef == "" {
				meta.GitRef = event.Run.Commit
			}
			if meta.GitBranch == "" {
				meta.GitBranch = ShareBranch(event.Run.Branch)
			}
			if meta.ProjectName == "" {
				meta.ProjectName = lastPathSegment(event.Run.Repository)
			}
		}
		if meta.GitBranch == "" {
			meta.GitBranch = ShareBranch(event.Branch)
		}
		if meta.ProjectName == "" && strings.TrimSpace(event.Repository) != "" {
			meta.ProjectName = lastPathSegment(event.Repository)
		}
		if meta.RelatedTo == "" && event.Handoff != nil && event.Handoff.SourceSessionID != "" && event.Handoff.SourceHarness != "" {
			meta.RelatedTo = ShareExternalID(event.Handoff.SourceHarness, event.Handoff.SourceSessionID)
			meta.RelationshipType = ShareRelationshipResume
		}
	}
	home := ""
	if !opts.NoHomeLookup {
		home = opts.HomeDirectory
		if home == "" {
			home, _ = os.UserHomeDir()
		}
	}
	if firstPrompt != "" {
		meta.Title = ShareTitle(newPathScrubber(firstNonEmptyString(opts.WorkingDirectory, workDir), home).text(firstPrompt))
	}
	best := 0
	for _, model := range modelOrder {
		if models[model] > best {
			meta.Model, best = model, models[model]
		}
	}
	if meta.ProjectName == "" && meta.GitRemoteURL != "" {
		meta.ProjectName = strings.TrimSuffix(lastPathSegment(meta.GitRemoteURL), ".git")
	}
	// The directory's own name, unless it is the home directory, whose name is the local account's.
	if meta.ProjectName == "" && workDir != "" && !samePath(workDir, home) && !samePath(workDir, opts.HomeDirectory) {
		meta.ProjectName = lastPathSegment(workDir)
	}
	if !usage.IsZero() {
		meta.TokenUsage = &usage
	}
	if hasCost {
		meta.CostUSD = &cost
	}
	return meta
}

// ShareTitle is a one-line title of at most ShareTitleMaxRunes runes from prompt text, without the
// handoff marker a resumed session's first prompt carries.
func ShareTitle(text string) string {
	if marker := handoffMarkerPattern.FindString(text); marker != "" {
		text = strings.ReplaceAll(text, marker, " ")
	}
	text = strings.Join(strings.Fields(text), " ")
	runes := []rune(text)
	if len(runes) <= ShareTitleMaxRunes {
		return text
	}
	return strings.TrimSpace(string(runes[:ShareTitleMaxRunes-1])) + "…"
}

// ShareRemoteURL removes credentials, query and fragment from a git remote URL, and the login of an
// scp-style remote, so a token embedded in an https remote never leaves the machine.
func ShareRemoteURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if scheme := strings.Index(raw, "://"); scheme >= 0 {
		rest := raw[scheme+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			host, path := rest[:slash], rest[slash:]
			if at := strings.LastIndex(host, "@"); at >= 0 {
				host = host[at+1:]
			}
			if cut := strings.IndexAny(path, "?#"); cut >= 0 {
				path = path[:cut]
			}
			return raw[:scheme+3] + host + path
		}
		if at := strings.LastIndex(rest, "@"); at >= 0 {
			rest = rest[at+1:]
		}
		return raw[:scheme+3] + rest
	}
	if at := strings.Index(raw, "@"); at >= 0 {
		colon := strings.Index(raw, ":")
		slash := strings.Index(raw, "/")
		if colon > at && (slash < 0 || colon < slash) {
			return raw[at+1:]
		}
	}
	return raw
}

// ShareBranch is a branch name worth reporting: "HEAD", which runtimes record for a detached
// checkout, names no branch.
func ShareBranch(name string) string {
	name = strings.TrimSpace(name)
	if name == "HEAD" {
		return ""
	}
	return name
}

func samePath(a, b string) bool {
	a, b = strings.TrimRight(strings.TrimSpace(a), `/\`), strings.TrimRight(strings.TrimSpace(b), `/\`)
	return a != "" && a == b
}

func lastPathSegment(value string) string {
	value = strings.TrimRight(strings.TrimSpace(value), `/\`)
	if i := strings.LastIndexAny(value, `/\:`); i >= 0 {
		value = value[i+1:]
	}
	return value
}
