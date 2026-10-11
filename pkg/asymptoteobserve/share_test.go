package asymptoteobserve

import (
	"encoding/json"
	"strings"
	"testing"
)

func shareEventAt(ts, harness, method, action, category string) Event {
	return Event{
		Timestamp:     ts,
		Vendor:        Vendor,
		Product:       Product,
		SchemaVersion: SchemaVersion,
		Event:         EventInfo{Kind: "agent_runtime", Action: action, Category: category},
		Severity:      SeverityInfo,
		Endpoint:      EndpointInfo{OS: "linux"},
		Harness:       HarnessInfo{Name: harness, CollectionMethod: method},
		Session:       &SessionInfo{ID: "sess-1", WorkingDirectory: "/home/dev/src/app"},
	}
}

func withCall(e Event, id, name string, args interface{}, result interface{}) Event {
	if e.GenAI == nil {
		e.GenAI = &GenAIInfo{}
	}
	e.GenAI.Tool = &GenAIToolInfo{Name: name, Call: &GenAIToolCallInfo{ID: id, Arguments: args, Result: result}}
	if e.Tool == nil {
		e.Tool = &ToolInfo{Name: name}
	}
	return e
}

var shareTestOpts = ShareOptions{HomeDirectory: "/home/dev"}

func partsOf(t *testing.T, messages []ShareMessageV1) []string {
	t.Helper()
	var out []string
	for _, m := range messages {
		for _, p := range m.Parts {
			out = append(out, m.Role+"/"+p.Type)
		}
	}
	return out
}

func TestBuildShareMessagesPairsClaudeHookPreAndPost(t *testing.T) {
	prompt := shareEventAt("2026-10-01T10:00:00.000000000Z", "claude_code", CollectionMethodHook, "prompt.submitted", "prompt")
	prompt.Event.ID = "e-prompt"
	prompt.Prompt = &PromptInfo{Text: "List the files in /home/dev/src/app please"}

	pre := shareEventAt("2026-10-01T10:00:01.000000000Z", "claude_code", CollectionMethodHook, "tool.invoked", "tool")
	pre.Event.ID = "e-pre"
	pre = withCall(pre, "toolu_1", "Bash", nil, nil)
	pre.Tool.Command = "ls -la /home/dev/src/app/cmd"
	pre.Command = &CommandInfo{Command: "ls -la /home/dev/src/app/cmd"}
	pre.Raw = map[string]interface{}{"tool_input": map[string]interface{}{"command": "ls -la /home/dev/src/app/cmd"}}

	post := shareEventAt("2026-10-01T10:00:02.000000000Z", "claude_code", CollectionMethodHook, "command.executed", "command")
	post.Event.ID = "e-post"
	post = withCall(post, "toolu_1", "Bash", nil, nil)
	post.Command = &CommandInfo{Command: "ls -la /home/dev/src/app/cmd", ExitCode: intPtr(0), Output: "main.go\n"}

	// The OTLP report of the same call: a second completion that only adds the duration.
	otlp := shareEventAt("2026-10-01T10:00:02.500000000Z", "claude_code", CollectionMethodOTLP, "command.executed", "command")
	otlp.Event.ID = "e-otlp"
	otlp = withCall(otlp, "toolu_1", "Bash", nil, nil)
	otlp.Command = &CommandInfo{Command: "ls -la /home/dev/src/app/cmd", DurationMS: 42}

	answer := shareEventAt("2026-10-01T10:00:03.000000000Z", "claude_code", CollectionMethodHook, "agent.message", "agent")
	answer.Event.ID = "e-answer"
	answer.Model = "claude-sonnet-5-5"
	answer.GenAI = &GenAIInfo{Output: &GenAIOutputInfo{Messages: TextOutputMessages("There is one file.")}}

	usage := shareEventAt("2026-10-01T10:00:03.000000000Z", "claude_code", CollectionMethodOTLP, "token.usage", "metric")
	usage.GenAI = &GenAIInfo{Usage: &GenAIUsageInfo{InputTokens: int64Ptr(10)}}

	// Given out of order, and with the session.shared record that must never become a message.
	shared := shareEventAt("2026-10-01T11:00:00.000000000Z", "claude_code", "", "session.shared", "session")
	messages := BuildShareMessagesWithOptions([]Event{answer, otlp, shared, post, usage, pre, prompt}, shareTestOpts)

	got := partsOf(t, messages)
	want := []string{"user/text", "assistant/tool_call", "assistant/tool_result", "assistant/text"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parts = %v, want %v", got, want)
	}
	for i, m := range messages {
		if m.Order != i+1 {
			t.Fatalf("message %d order = %d", i, m.Order)
		}
	}
	if messages[0].ID != "e-prompt" || messages[1].ID != "e-pre" || messages[2].ID != "e-post" {
		t.Fatalf("ids = %s %s %s", messages[0].ID, messages[1].ID, messages[2].ID)
	}
	if text := messages[0].Text; text != "List the files in . please" {
		t.Fatalf("prompt text not scrubbed: %q", text)
	}
	call := messages[1].Parts[0].Content.(*ShareToolCallContent)
	if call.CallID != "toolu_1" || call.ToolKind != ShareToolKindTerminalCommand || call.Command != "ls -la ./cmd" {
		t.Fatalf("call = %+v", call)
	}
	if call.Args["command"] != "ls -la ./cmd" {
		t.Fatalf("args = %+v", call.Args)
	}
	result := messages[2].Parts[0].Content.(*ShareToolResultContent)
	if result.CallID != "toolu_1" || result.Output != "main.go\n" || result.Status != ShareStatusSuccess {
		t.Fatalf("result = %+v", result)
	}
	if result.ExitCode == nil || *result.ExitCode != 0 || result.DurationMS == nil || *result.DurationMS != 42 {
		t.Fatalf("result exit/duration = %+v", result)
	}
	if messages[3].Model != "claude-sonnet-5-5" || messages[3].Text != "There is one file." {
		t.Fatalf("answer = %+v", messages[3])
	}
}

func TestBuildShareMessagesSynthesizesCallForPollCompletion(t *testing.T) {
	cmd := shareEventAt("2026-10-01T10:00:00Z", "codex", CollectionMethodPoll, "command.executed", "command")
	cmd.Event.ID = "e-cmd"
	cmd = withCall(cmd, "call_9", "exec_command", map[string]interface{}{"cmd": "go test ./..."}, nil)
	cmd.Command = &CommandInfo{Command: "go test ./...", ExitCode: intPtr(1), Output: "FAIL"}

	messages := BuildShareMessagesWithOptions([]Event{cmd}, shareTestOpts)
	if got := partsOf(t, messages); strings.Join(got, ",") != "assistant/tool_call,assistant/tool_result" {
		t.Fatalf("parts = %v", got)
	}
	if messages[0].ID == "e-cmd" || messages[1].ID != "e-cmd" {
		t.Fatalf("ids = %s %s", messages[0].ID, messages[1].ID)
	}
	again := BuildShareMessagesWithOptions([]Event{cmd}, shareTestOpts)
	if again[0].ID != messages[0].ID {
		t.Fatalf("synthesized call id is not stable: %s vs %s", again[0].ID, messages[0].ID)
	}
	call := messages[0].Parts[0].Content.(*ShareToolCallContent)
	if call.CallID != "call_9" || call.ToolKind != ShareToolKindTerminalCommand || call.Args["cmd"] != "go test ./..." {
		t.Fatalf("call = %+v", call)
	}
	result := messages[1].Parts[0].Content.(*ShareToolResultContent)
	if result.Status != ShareStatusError || result.ExitCode == nil || *result.ExitCode != 1 {
		t.Fatalf("result = %+v", result)
	}
}

func TestBuildShareMessagesPairsCallsWithoutRuntimeIDs(t *testing.T) {
	// Cursor-shaped: no tool call id on either hook. The edit's diff arrives on the completion and
	// belongs on the call.
	before := shareEventAt("2026-10-01T10:00:00Z", "cursor", CollectionMethodHook, "tool.invoked", "tool")
	before.Event.ID = "c-before"
	before.Tool = &ToolInfo{Name: "Shell", Command: "npm test"}
	before.Command = &CommandInfo{Command: "npm test"}
	after := shareEventAt("2026-10-01T10:00:05Z", "cursor", CollectionMethodHook, "command.executed", "command")
	after.Event.ID = "c-after"
	after.Tool = &ToolInfo{Name: "Shell", Command: "npm test"}
	after.Command = &CommandInfo{Command: "npm test", ExitCode: intPtr(0), Output: "ok"}
	edit := shareEventAt("2026-10-01T10:00:06Z", "cursor", CollectionMethodHook, "file.modified", "file")
	edit.Event.ID = "c-edit"
	edit.File = &FileInfo{Path: "/home/dev/src/app/main.go", Operation: "modify", Diff: "--- a/main.go\n+++ b/main.go\n"}
	read := shareEventAt("2026-10-01T10:00:07Z", "cursor", CollectionMethodHook, "file.read", "file")
	read.Event.ID = "c-read"
	read.File = &FileInfo{Path: "/home/dev/notes.txt", Operation: "read"}

	messages := BuildShareMessagesWithOptions([]Event{before, after, edit, read}, shareTestOpts)
	want := "assistant/tool_call,assistant/tool_result,assistant/tool_call,assistant/tool_result,assistant/tool_call"
	if got := partsOf(t, messages); strings.Join(got, ",") != want {
		t.Fatalf("parts = %v", got)
	}
	call := messages[0].Parts[0].Content.(*ShareToolCallContent)
	result := messages[1].Parts[0].Content.(*ShareToolResultContent)
	if result.CallID != call.CallID || call.CallID != "c-before" {
		t.Fatalf("not paired: call %q result %q", call.CallID, result.CallID)
	}
	editCall := messages[2].Parts[0].Content.(*ShareToolCallContent)
	if editCall.FilePath != "main.go" || editCall.ToolKind != ShareToolKindEdit || editCall.Diff == "" {
		t.Fatalf("edit call = %+v", editCall)
	}
	readCall := messages[4].Parts[0].Content.(*ShareToolCallContent)
	if readCall.FilePath != "~/notes.txt" || readCall.ToolKind != ShareToolKindRead {
		t.Fatalf("read call = %+v", readCall)
	}
}

func TestBuildShareMessagesTranscriptMCPAndApproval(t *testing.T) {
	invoke := shareEventAt("2026-10-01T10:00:00Z", "claude_code", CollectionMethodPoll, "mcp.tool_invoked", "mcp")
	invoke.Event.ID = "m-invoke"
	invoke = withCall(invoke, "toolu_m", "mcp__github__search", map[string]interface{}{"q": "beacon"}, nil)
	invoke.MCP = &MCPInfo{Server: "github", Tool: "search"}
	done := shareEventAt("2026-10-01T10:00:01Z", "claude_code", CollectionMethodPoll, "tool.completed", "tool")
	done.Event.ID = "m-done"
	done = withCall(done, "toolu_m", "mcp__github__search", nil, []interface{}{map[string]interface{}{"type": "text", "text": "3 results"}})
	approval := shareEventAt("2026-10-01T10:00:02Z", "opencode", CollectionMethodPlugin, "approval.denied", "approval")
	approval.Event.ID = "m-approval"
	approval.Approval = &ApprovalInfo{Required: true, Decision: "deny", Reason: "not now"}
	approval.Tool = &ToolInfo{Name: "bash"}
	start := shareEventAt("2026-09-30T10:00:00Z", "claude_code", CollectionMethodHook, "session.started", "session")
	start.Event.ID = "m-start"
	failure := shareEventAt("2026-10-01T10:00:03Z", "opencode", CollectionMethodPlugin, "session.error", "session")
	failure.Event.ID = "m-error"
	failure.Message = "provider returned 500"
	reasoning := shareEventAt("2026-10-01T10:00:04Z", "cursor", CollectionMethodHook, "agent.reasoning", "agent")
	reasoning.Event.ID = "m-think"
	reasoning.GenAI = &GenAIInfo{Output: &GenAIOutputInfo{Messages: ReasoningOutputMessages("Consider the cache.")}}

	messages := BuildShareMessagesWithOptions([]Event{invoke, done, approval, start, failure, reasoning}, shareTestOpts)
	want := "system/system_event,assistant/tool_call,assistant/tool_result,system/system_event,system/error,assistant/thinking"
	if got := partsOf(t, messages); strings.Join(got, ",") != want {
		t.Fatalf("parts = %v", got)
	}
	call := messages[1].Parts[0].Content.(*ShareToolCallContent)
	if call.ToolKind != ShareToolKindMCP || call.Args["q"] != "beacon" {
		t.Fatalf("mcp call = %+v", call)
	}
	if result := messages[2].Parts[0].Content.(*ShareToolResultContent); result.Output != "3 results" || result.CallID != "toolu_m" {
		t.Fatalf("mcp result = %+v", result)
	}
	ev := messages[3].Parts[0].Content.(map[string]interface{})
	if ev["subtype"] != "approval" || ev["decision"] != "deny" || ev["toolName"] != "bash" {
		t.Fatalf("approval = %+v", ev)
	}
	if messages[4].Parts[0].Content.(ShareErrorContent).Message != "provider returned 500" {
		t.Fatalf("error = %+v", messages[4])
	}
}

func TestBuildShareMessagesSanitizesContent(t *testing.T) {
	prompt := shareEventAt("2026-10-01T10:00:00Z", "codex", CollectionMethodHook, "prompt.submitted", "prompt")
	prompt.Prompt = &PromptInfo{Text: "use api_key=supersecretvalue123 to call it"}
	cmd := shareEventAt("2026-10-01T10:00:01Z", "codex", CollectionMethodHook, "command.executed", "command")
	cmd.Command = &CommandInfo{Command: "curl -H 'Authorization: Bearer abc.def.ghi' x", Output: "token=zzzzzzzzzzzz"}

	messages := BuildShareMessagesWithOptions([]Event{prompt, cmd}, shareTestOpts)
	data, err := json.Marshal(messages)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"supersecretvalue123", "abc.def.ghi", "zzzzzzzzzzzz"} {
		if strings.Contains(string(data), secret) {
			t.Fatalf("secret %q reached the payload: %s", secret, data)
		}
	}
	if messages[0].ID == "" || messages[0].ID != ShareMessageID(prompt) {
		t.Fatalf("derived id %q does not match ShareMessageID", messages[0].ID)
	}
}

func TestBuildShareMessagesIsDeterministic(t *testing.T) {
	a := shareEventAt("2026-10-01T10:00:00Z", "codex", CollectionMethodHook, "prompt.submitted", "prompt")
	a.Event.ID = "b"
	a.Prompt = &PromptInfo{Text: "one"}
	b := shareEventAt("2026-10-01T10:00:00Z", "codex", CollectionMethodHook, "prompt.submitted", "prompt")
	b.Event.ID = "a"
	b.Prompt = &PromptInfo{Text: "two"}
	first, _ := json.Marshal(BuildShareMessagesWithOptions([]Event{a, b}, shareTestOpts))
	second, _ := json.Marshal(BuildShareMessagesWithOptions([]Event{b, a}, shareTestOpts))
	if string(first) != string(second) {
		t.Fatalf("order depends on input:\n%s\n%s", first, second)
	}
	if !strings.Contains(string(first), `"id":"a","order":1`) {
		t.Fatalf("ties are not broken by id: %s", first)
	}
}

func TestShareToolKind(t *testing.T) {
	cases := []struct {
		name, action, category string
		mcp                    bool
		want                   string
	}{
		{"Bash", "tool.invoked", "tool", false, ShareToolKindTerminalCommand},
		{"exec_command", "", "", false, ShareToolKindTerminalCommand},
		{"run_terminal_cmd", "", "", false, ShareToolKindTerminalCommand},
		{"shell", "", "", false, ShareToolKindTerminalCommand},
		{"Read", "", "", false, ShareToolKindRead},
		{"view", "", "", false, ShareToolKindRead},
		{"read_file", "", "", false, ShareToolKindRead},
		{"Edit", "", "", false, ShareToolKindEdit},
		{"MultiEdit", "", "", false, ShareToolKindEdit},
		{"apply_patch", "", "", false, ShareToolKindEdit},
		{"str_replace_editor", "", "", false, ShareToolKindEdit},
		{"Write", "", "", false, ShareToolKindWrite},
		{"create_file", "", "", false, ShareToolKindWrite},
		{"Grep", "", "", false, ShareToolKindGrep},
		{"Glob", "", "", false, ShareToolKindGlob},
		{"WebSearch", "", "", false, ShareToolKindWebSearch},
		{"WebFetch", "", "", false, ShareToolKindWebFetch},
		{"Task", "", "", false, ShareToolKindTask},
		{"TodoWrite", "", "", false, ShareToolKindTodo},
		{"update_plan", "", "", false, ShareToolKindTodo},
		{"mcp__github__search", "", "", false, ShareToolKindMCP},
		{"search_issues", "mcp.tool_invoked", "mcp", true, ShareToolKindMCP},
		{"", "file.read", "file", false, ShareToolKindRead},
		{"", "file.created", "file", false, ShareToolKindWrite},
		{"", "command.executed", "command", false, ShareToolKindTerminalCommand},
		{"frobnicate", "tool.invoked", "tool", false, ShareToolKindOther},
	}
	for _, tc := range cases {
		if got := ShareToolKind(tc.name, tc.action, tc.category, tc.mcp); got != tc.want {
			t.Errorf("ShareToolKind(%q, %q) = %q, want %q", tc.name, tc.action, got, tc.want)
		}
	}
}

func TestShareExternalID(t *testing.T) {
	cases := []struct{ harness, session, want string }{
		{"claude", "3f1c2e4a-0000-4000-8000-000000000001", "claude_code:3f1c2e4a-0000-4000-8000-000000000001"},
		{"codex", "rollout:abc.1", "codex_cli:rollout:abc.1"},
		{"cursor", "has spaces/slash", "cursor:sha256-"},
		{"claude_code", strings.Repeat("a", 300), "claude_code:sha256-"},
	}
	for _, tc := range cases {
		got := ShareExternalID(tc.harness, tc.session)
		if !ValidShareExternalID(got) {
			t.Fatalf("ShareExternalID(%q, %q) = %q is not a valid external id", tc.harness, tc.session, got)
		}
		if tc.want != "" && !strings.HasPrefix(got, tc.want) {
			t.Fatalf("ShareExternalID(%q, %q) = %q, want prefix %q", tc.harness, tc.session, got, tc.want)
		}
	}
	hashed := ShareExternalID("cursor", "has spaces/slash")
	if !strings.HasPrefix(hashed, "cursor:sha256-") || len(hashed) != len("cursor:sha256-")+32 {
		t.Fatalf("hashed id = %q", hashed)
	}
	if ShareExternalID("cursor", "has spaces/slash") != hashed {
		t.Fatal("hashed id is not stable")
	}
}

func TestShareMetadataFromEvents(t *testing.T) {
	start := shareEventAt("2026-10-01T10:00:00Z", "claude", CollectionMethodHook, "session.started", "session")
	start.Branch = "main"
	prompt := shareEventAt("2026-10-01T10:00:01Z", "claude", CollectionMethodHook, "prompt.submitted", "prompt")
	prompt.Prompt = &PromptInfo{Text: "Fix the flaky login test in /home/dev/src/app/login_test.go, it fails about one run in ten on CI and I want it gone\n[beacon-handoff from=codex session=abc123]"}
	m1 := shareEventAt("2026-10-01T10:00:02Z", "claude", CollectionMethodOTLP, "agent.message", "agent")
	m1.Model = "claude-sonnet-5-5"
	m1.GenAI = &GenAIInfo{Usage: &GenAIUsageInfo{InputTokens: int64Ptr(100), OutputTokens: int64Ptr(20), CostUSD: float64Ptr(0.25),
		CacheRead: &GenAIUsageCacheReadInfo{InputTokens: int64Ptr(5)}}}
	m2 := shareEventAt("2026-10-01T10:00:03Z", "claude", CollectionMethodOTLP, "agent.message", "agent")
	m2.Model = "claude-sonnet-5-5"
	m2.GenAI = &GenAIInfo{Usage: &GenAIUsageInfo{InputTokens: int64Ptr(50), Reasoning: &GenAIUsageReasoningInfo{OutputTokens: int64Ptr(7)}}}
	m3 := shareEventAt("2026-10-01T10:00:04Z", "claude", CollectionMethodOTLP, "agent.message", "agent")
	m3.Model = "claude-haiku-5"
	link := shareEventAt("2026-10-01T10:00:05Z", "claude", "", "session.commit_linked", "session")
	link.VCS = &VCSInfo{
		Ref:        &VCSRefInfo{Head: &VCSRefHeadInfo{Revision: "abc123def", Name: "main", Type: "branch"}},
		Repository: &VCSRepositoryInfo{URL: &VCSRepositoryURLInfo{Full: "https://x-access-token:ghp_secret@github.com/acme/repo.git?x=1"}},
	}
	handoff := shareEventAt("2026-10-01T10:00:01Z", "claude", CollectionMethodHook, "session.handoff", "session")
	handoff.Handoff = &HandoffInfo{SourceHarness: "codex", SourceSessionID: "abc123"}

	meta := ShareMetadataFromEventsWithOptions([]Event{link, m3, m2, m1, prompt, handoff, start}, shareTestOpts)
	if meta.SchemaVersion != ShareSchemaVersion || meta.AgentID != "claude_code" || meta.Source != ShareSourceCLI {
		t.Fatalf("identity = %+v", meta)
	}
	if meta.Title != "Fix the flaky login test in ./login_test.go, it fails about one run in ten on C…" {
		t.Fatalf("title = %q", meta.Title)
	}
	if n := len([]rune(meta.Title)); n > ShareTitleMaxRunes {
		t.Fatalf("title has %d runes", n)
	}
	if meta.Model != "claude-sonnet-5-5" {
		t.Fatalf("model = %q", meta.Model)
	}
	want := ShareTokenUsageV1{InputTokens: 150, OutputTokens: 20, CacheReadInputTokens: 5, ReasoningOutputTokens: 7}
	if meta.TokenUsage == nil || *meta.TokenUsage != want || meta.CostUSD == nil || *meta.CostUSD != 0.25 {
		t.Fatalf("usage = %+v cost = %v", meta.TokenUsage, meta.CostUSD)
	}
	if meta.GitRemoteURL != "https://github.com/acme/repo.git" || meta.GitBranch != "main" || meta.GitRef != "abc123def" {
		t.Fatalf("git = %q %q %q", meta.GitRemoteURL, meta.GitBranch, meta.GitRef)
	}
	if meta.ProjectName != "repo" {
		t.Fatalf("project = %q", meta.ProjectName)
	}
	if meta.SourceSessionID != "sess-1" || meta.SourceCreatedAt != "2026-10-01T10:00:00Z" || meta.SourceUpdatedAt != "2026-10-01T10:00:05Z" {
		t.Fatalf("source = %+v", meta)
	}
	if meta.RelatedTo != "codex_cli:abc123" || meta.RelationshipType != ShareRelationshipResume {
		t.Fatalf("related = %q %q", meta.RelatedTo, meta.RelationshipType)
	}
}

func TestShareRemoteURL(t *testing.T) {
	cases := map[string]string{
		"https://user:pw@github.com/acme/repo.git": "https://github.com/acme/repo.git",
		"git@github.com:acme/repo.git":             "github.com:acme/repo.git",
		"ssh://git@host:22/acme/repo":              "ssh://host:22/acme/repo",
		"https://github.com/acme/repo?token=abc":   "https://github.com/acme/repo",
		"":                                         "",
	}
	for in, want := range cases {
		if got := ShareRemoteURL(in); got != want {
			t.Errorf("ShareRemoteURL(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestShareWireShape pins the JSON field names and shapes of the beacon.share.v1 contract, so a
// rename here cannot drift from what beacon.sh accepts.
func TestShareWireShape(t *testing.T) {
	message := ShareMessageV1{
		ID: "m1", Order: 1, Role: ShareRoleAssistant, Timestamp: "2026-10-01T10:00:00Z", Model: "m", Text: "t",
		Parts: []SharePartV1{
			{Type: SharePartToolCall, Order: 1, Content: &ShareToolCallContent{CallID: "c", ToolName: "Bash", ToolKind: ShareToolKindTerminalCommand, Args: map[string]interface{}{}, Command: "ls", FilePath: "a", Diff: "d"}},
			{Type: SharePartToolResult, Order: 2, Content: &ShareToolResultContent{CallID: "c", ToolName: "Bash", Output: "o", Status: ShareStatusSuccess, ExitCode: intPtr(0), DurationMS: int64Ptr(3)}},
			{Type: SharePartText, Order: 3, Content: ShareTextContent{Text: "x"}},
			{Type: SharePartError, Order: 4, Content: ShareErrorContent{Message: "e"}},
			{Type: SharePartSystemEvent, Order: 5, Content: map[string]interface{}{"subtype": "session.started"}},
		},
		TokenUsage: &ShareTokenUsageV1{InputTokens: 1},
	}
	got, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"m1","order":1,"role":"assistant","timestamp":"2026-10-01T10:00:00Z","model":"m","text":"t","parts":[` +
		`{"type":"tool_call","order":1,"content":{"callId":"c","toolName":"Bash","toolKind":"terminal_command","args":{},"command":"ls","filePath":"a","diff":"d"}},` +
		`{"type":"tool_result","order":2,"content":{"callId":"c","toolName":"Bash","output":"o","status":"success","exitCode":0,"durationMs":3}},` +
		`{"type":"text","order":3,"content":{"text":"x"}},` +
		`{"type":"error","order":4,"content":{"message":"e"}},` +
		`{"type":"system_event","order":5,"content":{"subtype":"session.started"}}],` +
		`"token_usage":{"input_tokens":1,"output_tokens":0,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"reasoning_output_tokens":0}}`
	if string(got) != want {
		t.Fatalf("message JSON drifted:\n got %s\nwant %s", got, want)
	}

	trace := ShareTraceV1{
		SchemaVersion: ShareSchemaVersion, AgentID: "claude_code", Title: "t", Visibility: ShareVisibilityDirect, Model: "m",
		ProjectName: "p", GitRemoteURL: "u", GitBranch: "b", GitRef: "r", TokenUsage: &ShareTokenUsageV1{}, CostUSD: float64Ptr(0),
		SourceSessionID: "s", SourceCreatedAt: "c", SourceUpdatedAt: "d", RelatedTo: "x", RelationshipType: ShareRelationshipSubagent, Source: ShareSourceCLI,
	}
	got, err = json.Marshal(trace)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"schema_version":"beacon.share.v1","agent_id":"claude_code","title":"t","visibility":"direct","model":"m",` +
		`"project_name":"p","git_remote_url":"u","git_branch":"b","git_ref":"r",` +
		`"token_usage":{"input_tokens":0,"output_tokens":0,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"reasoning_output_tokens":0},` +
		`"cost_usd":0,"source_session_id":"s","source_created_at":"c","source_updated_at":"d","related_to":"x","relationship_type":"subagent","source":"cli"}`
	if string(got) != want {
		t.Fatalf("trace JSON drifted:\n got %s\nwant %s", got, want)
	}

	var state ShareTraceStateV1
	if err := json.Unmarshal([]byte(`{"id":"k3x","url":"https://beacon.sh/s/k3x","visibility":"direct","message_count":4,"last_message_id":"m4","max_order":4}`), &state); err != nil {
		t.Fatal(err)
	}
	if state.LastMessageID != "m4" || state.MaxOrder != 4 || state.MessageCount != 4 {
		t.Fatalf("state = %+v", state)
	}
	var put ShareTraceResultV1
	if err := json.Unmarshal([]byte(`{"id":"k3x","external_id":"claude_code:abc","url":"https://beacon.sh/s/k3x","visibility":"direct","message_count":0,"created":true}`), &put); err != nil {
		t.Fatal(err)
	}
	if !put.Created || put.ExternalID != "claude_code:abc" {
		t.Fatalf("put = %+v", put)
	}
}

func TestShareMetadataLeavesOutDetachedHeadAndTheHomeDirectoryName(t *testing.T) {
	event := shareEventAt("2026-10-01T10:00:00Z", "claude_code", CollectionMethodPoll, "prompt.submitted", "prompt")
	event.Session.WorkingDirectory = "/home/dev"
	event.Branch = "HEAD"
	event.Prompt = &PromptInfo{Text: "hi"}
	meta := ShareMetadataFromEventsWithOptions([]Event{event}, shareTestOpts)
	if meta.GitBranch != "" || meta.ProjectName != "" {
		t.Fatalf("branch = %q, project = %q", meta.GitBranch, meta.ProjectName)
	}
	event.Session.WorkingDirectory = "/home/dev/src/app"
	if meta := ShareMetadataFromEventsWithOptions([]Event{event}, shareTestOpts); meta.ProjectName != "app" {
		t.Fatalf("project = %q", meta.ProjectName)
	}
}

func TestPathScrubberReplacesWholePathsOnly(t *testing.T) {
	s := newPathScrubber("/src/proj", "/home/al")
	cases := map[string]string{
		"/src/proj":                     ".",
		"/src/proj/main.go":             "./main.go",
		"cd /src/proj && go test":       "cd . && go test",
		`"/src/proj/a.go"`:              `"./a.go"`,
		"/src/proj-old/main.go":         "/src/proj-old/main.go",
		"/src/project/main.go":          "/src/project/main.go",
		"/home/al/notes.txt":            "~/notes.txt",
		"/home/alex/notes.txt":          "/home/alex/notes.txt",
		"/srv/home/al/x":                "/srv/home/al/x",
		"open /home/al, then /home/al.": "open ~, then ~.",
		"/home/al/src/proj/x":           "~/src/proj/x",
	}
	for in, want := range cases {
		if got := s.text(in); got != want {
			t.Errorf("text(%q) = %q, want %q", in, got, want)
		}
	}
	if got := s.path("/src/proj-old/main.go"); got != "/src/proj-old/main.go" {
		t.Errorf("path of a sibling directory = %q", got)
	}
	win := newPathScrubber(`C:\work\proj`, `C:\Users\al`)
	if got := win.text(`C:\work\proj\a.go and C:\Users\alex\b`); got != `.\a.go and C:\Users\alex\b` {
		t.Errorf("windows text = %q", got)
	}
}

func TestBuildShareMessagesKeepsRepeatedPhaselessCallsApart(t *testing.T) {
	// Cursor's beforeReadFile records file.read with a path and nothing else. Reading the same file
	// twice is two calls, not a call and its result.
	var events []Event
	for i, ts := range []string{"2026-10-01T10:00:00Z", "2026-10-01T10:00:01Z", "2026-10-01T10:00:02Z"} {
		read := shareEventAt(ts, "cursor", CollectionMethodHook, "file.read", "file")
		read.Event.ID = "r-" + string(rune('a'+i))
		read.File = &FileInfo{Path: "/home/dev/src/app/main.go", Operation: "read"}
		events = append(events, read)
	}
	messages := BuildShareMessagesWithOptions(events, shareTestOpts)
	want := "assistant/tool_call,assistant/tool_call,assistant/tool_call"
	if got := partsOf(t, messages); strings.Join(got, ",") != want {
		t.Fatalf("parts = %v", got)
	}
}
