package cmd

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/pflag"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/dashboard"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/schema"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/writer"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/handoff"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/testenv"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

const shareTestSession = "5f0c1d2e-aaaa-4bbb-8ccc-000000000001"

// shareEnv isolates one share test: a home, a runtime log, a stub Claude Code store holding one
// session in projectDir, and seams that fail the test on any network use unless a test opts in.
type shareEnv struct {
	home       string
	projectDir string
	logPath    string
}

func newShareEnv(t *testing.T) *shareEnv {
	t.Helper()
	home := t.TempDir()
	testenv.SetHome(t, home)
	env := &shareEnv{home: home, projectDir: filepath.Join(home, "src", "app"), logPath: filepath.Join(home, "runtime.jsonl")}
	if err := os.MkdirAll(env.projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stubHandoffSources(t, stubHandoffSource{
		harness: handoff.HarnessClaude,
		sessions: []handoff.Session{{
			Harness: handoff.HarnessClaude, ID: shareTestSession, Title: "Fix the login test",
			Directory: env.projectDir, SourcePath: filepath.Join(home, "store", shareTestSession+".jsonl"),
			UpdatedAt: time.Now(),
		}},
		events: shareFixtureEvents(env.projectDir),
	})
	prevLoad, prevClient, prevTTY, prevStdin, prevGetenv, prevRemote := shareAccountLoad, shareHTTPClient, shareIsTTY, shareStdin, shareGetenv, shareGitRemote
	shareAccountLoad = func() (*account.Session, error) { return nil, account.ErrNotSignedIn }
	shareHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Errorf("unexpected network request: %s %s", r.Method, r.URL)
		return nil, errors.New("no network in tests")
	})}
	shareIsTTY = func() bool { return false }
	shareStdin = strings.NewReader("")
	shareGetenv = func(string) string { return "" }
	shareGitRemote = func(string) string { return "" }
	t.Cleanup(func() {
		shareAccountLoad, shareHTTPClient, shareIsTTY, shareStdin, shareGetenv, shareGitRemote = prevLoad, prevClient, prevTTY, prevStdin, prevGetenv, prevRemote
	})
	return env
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func shareFixtureEvents(dir string) []schema.Event {
	base := func(ts, action, category string) schema.Event {
		e := schema.NewEvent(schema.NewEventOptions{Action: action, Category: category, Harness: schema.HarnessInfo{Name: handoff.HarnessClaude, CollectionMethod: schema.CollectionMethodPoll}})
		e.Timestamp = ts
		e.Session = &schema.SessionInfo{ID: shareTestSession, WorkingDirectory: dir}
		return e
	}
	prompt := base("2026-10-01T10:00:00.000000000Z", "prompt.submitted", "prompt")
	prompt.Prompt = &schema.PromptInfo{Text: "Fix the login test in " + dir + "/login_test.go"}
	call := base("2026-10-01T10:00:01.000000000Z", "tool.invoked", "tool")
	call.Tool = &schema.ToolInfo{Name: "Bash", Command: "go test ./..."}
	call.GenAI = &schema.GenAIInfo{Tool: &schema.GenAIToolInfo{Name: "Bash", Call: &schema.GenAIToolCallInfo{ID: "toolu_1", Arguments: map[string]interface{}{"command": "go test ./..."}}}}
	done := base("2026-10-01T10:00:02.000000000Z", "command.executed", "command")
	done.Tool = &schema.ToolInfo{Name: "Bash", Command: "go test ./..."}
	done.Command = &schema.CommandInfo{Command: "go test ./...", Output: "ok"}
	done.GenAI = &schema.GenAIInfo{Tool: &schema.GenAIToolInfo{Name: "Bash", Call: &schema.GenAIToolCallInfo{ID: "toolu_1"}}}
	answer := base("2026-10-01T10:00:03.000000000Z", "agent.message", "agent")
	answer.Model = "claude-sonnet-5-5"
	answer.GenAI = &schema.GenAIInfo{Output: &schema.GenAIOutputInfo{Messages: asymptoteobserve.TextOutputMessages("Fixed.")}}
	return []schema.Event{prompt, call, done, answer}
}

func runShareCommand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	shareOpts = shareOptions{}
	for _, cmd := range []*pflag.FlagSet{shareCmd.Flags(), shareRefreshCmd.Flags()} {
		cmd.VisitAll(func(f *pflag.Flag) {
			if slice, ok := f.Value.(pflag.SliceValue); ok {
				_ = slice.Replace(nil)
				f.Changed = false
				return
			}
			_ = f.Value.Set(f.DefValue)
			f.Changed = false
		})
	}
	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(append([]string{"share"}, args...))
	t.Cleanup(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	})
	err := rootCmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestShareFlagValidation(t *testing.T) {
	env := newShareEnv(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--visibility", "everyone"}, "--visibility must be"},
		{[]string{"--session", "abc", "--cwd", env.projectDir}, "none of the others can be"},
		{[]string{"--session", "abc", "--source-path", "x"}, "none of the others can be"},
		{[]string{"--list", "--session", shareTestSession}, "--list shows candidates"},
		{[]string{"--list", "--print"}, "cannot be combined"},
		{[]string{"--harness", "notaruntime", "--print"}, "unsupported runtime"},
	} {
		_, _, err := runShareCommand(t, append(tc.args, "--log-path", env.logPath)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("share %v: err = %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestShareDryRunPrintsThePayloadWithoutNetwork(t *testing.T) {
	env := newShareEnv(t)
	stdout, _, err := runShareCommand(t, "--cwd", env.projectDir, "--print", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("share --print: %v", err)
	}
	var payload sharePayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("payload is not JSON: %v\n%s", err, stdout)
	}
	if payload.ExternalID != "claude_code:"+shareTestSession || payload.Trace.AgentID != "claude_code" {
		t.Fatalf("identity = %q %q", payload.ExternalID, payload.Trace.AgentID)
	}
	if payload.Trace.Title != "Fix the login test" || payload.Trace.Visibility != "" || payload.Trace.ProjectName != "app" {
		t.Fatalf("trace = %+v", payload.Trace)
	}
	if len(payload.Messages) != 4 {
		t.Fatalf("messages = %d: %s", len(payload.Messages), stdout)
	}
	if strings.Contains(stdout, env.home) {
		t.Fatalf("the payload names the local home directory:\n%s", stdout)
	}
	if !strings.Contains(stdout, "./login_test.go") {
		t.Fatalf("the prompt path was not made relative:\n%s", stdout)
	}
	if _, err := os.Stat(env.logPath); !os.IsNotExist(err) {
		t.Fatalf("a dry run wrote the runtime log: %v", err)
	}
	// --dry-run is the same, and --session takes a prefix.
	again, _, err := runShareCommand(t, "--session", shareTestSession[:8], "--dry-run", "--log-path", env.logPath)
	if err != nil || again != stdout {
		t.Fatalf("--dry-run --session prefix differs (err %v)", err)
	}
}

func TestShareResolvesSessionsBySourcePathAndFromTheLog(t *testing.T) {
	env := newShareEnv(t)
	source := filepath.Join(env.home, "store", shareTestSession+".jsonl")
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runShareCommand(t, "--source-path", source, "--print", "--log-path", env.logPath)
	if err != nil || !strings.Contains(stdout, shareTestSession) {
		t.Fatalf("--source-path: err=%v out=%s", err, stdout)
	}

	// A Gemini CLI session exists only in the runtime log, in another directory.
	other := filepath.Join(env.home, "src", "tool")
	prompt := schema.NewEvent(schema.NewEventOptions{Action: "prompt.submitted", Category: "prompt", Harness: schema.HarnessInfo{Name: "gemini_cli", CollectionMethod: schema.CollectionMethodHook}})
	prompt.Session = &schema.SessionInfo{ID: "gem-session-1", WorkingDirectory: other}
	prompt.Prompt = &schema.PromptInfo{Text: "Add a flag"}
	if _, err := writer.AppendEvent(prompt, writer.Options{Path: env.logPath, UserMode: true}); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = runShareCommand(t, "--cwd", other, "--print", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("--cwd from log: %v", err)
	}
	var payload sharePayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil || payload.ExternalID != "gemini_cli:gem-session-1" || len(payload.Messages) != 1 {
		t.Fatalf("log payload = %+v (err %v)", payload, err)
	}

	list, _, err := runShareCommand(t, "--list", "--cwd", env.home, "--json", "--log-path", env.logPath)
	if err != nil {
		t.Fatal(err)
	}
	var listed struct {
		OK   bool `json:"ok"`
		Data struct {
			Sessions []handoff.Session `json:"sessions"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(list), &listed); err != nil || !listed.OK || len(listed.Data.Sessions) != 2 {
		t.Fatalf("list = %s (err %v)", list, err)
	}

	_, _, err = runShareCommand(t, "--cwd", filepath.Join(env.home, "empty"), "--print", "--log-path", env.logPath)
	if err == nil || !strings.Contains(err.Error(), "no agent session found") {
		t.Fatalf("empty dir: err = %v", err)
	}
}

// fakeShareServer is beacon.sh's shared-trace API, in memory.
type fakeShareServer struct {
	mu       sync.Mutex
	server   *httptest.Server
	trace    *asymptoteobserve.ShareTraceV1
	messages []asymptoteobserve.ShareMessageV1
	requests []string
	auth     map[string]bool
	// failBatches makes every message upload fail, as an outage would.
	failBatches bool
}

func newFakeShareServer(t *testing.T) *fakeShareServer {
	f := &fakeShareServer{auth: map[string]bool{}}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.requests = append(f.requests, r.Method+" "+r.URL.Path)
		f.auth[r.Header.Get("Authorization")] = true
		id := strings.TrimPrefix(r.URL.Path, "/v1/traces/")
		switch {
		case r.Method == http.MethodPut:
			var trace asymptoteobserve.ShareTraceV1
			_ = json.NewDecoder(r.Body).Decode(&trace)
			created := f.trace == nil
			if !created && trace.Visibility == "" {
				trace.Visibility = f.trace.Visibility
			}
			if !created && trace.Title == "" {
				trace.Title = f.trace.Title
			}
			if trace.Visibility == "" {
				trace.Visibility = "direct"
			}
			f.trace = &trace
			fmt.Fprintf(w, `{"id":"k3xabc","external_id":%q,"url":"https://beacon.sh/s/k3xabc","visibility":%q,"message_count":%d,"created":%v}`, id, trace.Visibility, len(f.messages), created)
		case r.Method == http.MethodPost && strings.HasSuffix(id, "/messages/batch"):
			if f.failBatches {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, "want gzip", 400)
				return
			}
			data, _ := io.ReadAll(zr)
			var batch asymptoteobserve.ShareMessagesBatchV1
			_ = json.Unmarshal(data, &batch)
			for _, m := range batch.Messages {
				replaced := false
				for i := range f.messages {
					if f.messages[i].ID == m.ID {
						f.messages[i], replaced = m, true
					}
				}
				if !replaced {
					f.messages = append(f.messages, m)
				}
			}
			fmt.Fprintf(w, `{"accepted":%d,"message_count":%d}`, len(batch.Messages), len(f.messages))
		case r.Method == http.MethodGet:
			if f.trace == nil {
				http.NotFound(w, r)
				return
			}
			last, maxOrder := "", 0
			for _, m := range f.messages {
				if m.Order > maxOrder {
					last, maxOrder = m.ID, m.Order
				}
			}
			fmt.Fprintf(w, `{"id":"k3xabc","url":"https://beacon.sh/s/k3xabc","visibility":%q,"message_count":%d,"last_message_id":%q,"max_order":%d}`, f.trace.Visibility, len(f.messages), last, maxOrder)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeShareServer) signIn(scopes ...string) {
	session := &account.Session{BaseURL: f.server.URL, AccessToken: "bcn_cli_secret_token", TokenType: "Bearer", User: account.User{ID: "u1", Email: "dev@example.com"}, Scopes: scopes}
	shareAccountLoad = func() (*account.Session, error) { return session, nil }
	shareHTTPClient = f.server.Client()
}

func TestShareUploadsAndRecordsTheShareLocally(t *testing.T) {
	env := newShareEnv(t)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)

	stdout, stderr, err := runShareCommand(t, "--cwd", env.projectDir, "--json", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("share: %v\n%s", err, stderr)
	}
	var result struct {
		OK   bool        `json:"ok"`
		Data shareResult `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil || !result.OK {
		t.Fatalf("output = %s (err %v)", stdout, err)
	}
	want := shareResult{TraceID: "k3xabc", ExternalID: "claude_code:" + shareTestSession, SharedURL: "https://beacon.sh/s/k3xabc", Visibility: "direct", AgentID: "claude_code", MessageCount: 4, Uploaded: 4, SelectedBy: "recent"}
	if result.Data != want {
		t.Fatalf("result = %+v, want %+v", result.Data, want)
	}
	if strings.Contains(stdout+stderr, "bcn_cli_secret_token") {
		t.Fatal("the account token reached the output")
	}
	if !srv.auth["Bearer bcn_cli_secret_token"] || len(srv.messages) != 4 || srv.trace.SchemaVersion != asymptoteobserve.ShareSchemaVersion {
		t.Fatalf("server saw auth=%v messages=%d trace=%+v", srv.auth, len(srv.messages), srv.trace)
	}
	if srv.trace.Visibility != "" && srv.trace.Visibility != "direct" {
		t.Fatalf("visibility sent = %q", srv.trace.Visibility)
	}

	// The local trace list now shows the session as shared.
	list, err := dashboard.ReadTraceList(env.logPath, dashboard.TraceQuery{State: "shared"})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Traces) != 1 || list.Traces[0].Sharing.URL != "https://beacon.sh/s/k3xabc" || list.Traces[0].Sharing.Visibility != "direct" || list.Traces[0].Sharing.SharedAt == "" {
		t.Fatalf("shared traces = %+v", list.Traces)
	}
	data, err := os.ReadFile(env.logPath)
	if err != nil {
		t.Fatal(err)
	}
	var event schema.Event
	if err := json.Unmarshal(bytes.TrimSpace(data), &event); err != nil {
		t.Fatal(err)
	}
	if event.Event.Action != SessionSharedAction || event.Event.Fidelity != asymptoteobserve.FidelityInferred || event.Harness.CollectionMethod != "" || event.Session.ID != shareTestSession {
		t.Fatalf("session.shared event = %+v", event)
	}

	// Sharing again updates the same trace: nothing duplicates and the visibility is kept.
	if _, _, err := runShareCommand(t, "--cwd", env.projectDir, "--log-path", env.logPath); err != nil {
		t.Fatal(err)
	}
	if len(srv.messages) != 4 {
		t.Fatalf("re-share duplicated messages: %d", len(srv.messages))
	}

	// A refresh sends what the server does not have, plus the call it holds without a result
	// (the prompt and the Bash call are on the server; the call is re-sent with its result).
	srv.mu.Lock()
	srv.messages = srv.messages[:2]
	srv.mu.Unlock()
	stdout, _, err = runShareCommand(t, "refresh", "claude_code:"+shareTestSession, "--json", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil || result.Data.Uploaded != 3 || result.Data.MessageCount != 4 {
		t.Fatalf("refresh result = %s (err %v)", stdout, err)
	}
}

func TestSharePublicNeedsConfirmation(t *testing.T) {
	env := newShareEnv(t)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)

	_, _, err := runShareCommand(t, "--cwd", env.projectDir, "--visibility", "public", "--log-path", env.logPath)
	if err == nil || !strings.Contains(err.Error(), "--yes") || len(srv.requests) != 0 {
		t.Fatalf("non-terminal public share: err = %v, requests = %v", err, srv.requests)
	}

	shareIsTTY = func() bool { return true }
	for _, key := range []string{"CI", "CONTINUOUS_INTEGRATION", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "JENKINS_URL", "TEAMCITY_VERSION"} {
		t.Setenv(key, "")
	}
	shareStdin = strings.NewReader("n\n")
	_, stderr, err := runShareCommand(t, "--cwd", env.projectDir, "--visibility", "public", "--log-path", env.logPath)
	if err == nil || !strings.Contains(stderr, "publicly?") || len(srv.requests) != 0 {
		t.Fatalf("declined public share: err = %v, requests = %v, stderr = %s", err, srv.requests, stderr)
	}

	shareStdin = strings.NewReader("y\n")
	if _, _, err := runShareCommand(t, "--cwd", env.projectDir, "--visibility", "public", "--log-path", env.logPath); err != nil {
		t.Fatalf("confirmed public share: %v", err)
	}
	if srv.trace == nil || srv.trace.Visibility != "public" {
		t.Fatalf("trace = %+v", srv.trace)
	}

	shareIsTTY = func() bool { return false }
	if _, _, err := runShareCommand(t, "--cwd", env.projectDir, "--visibility", "public", "--yes", "--log-path", env.logPath); err != nil {
		t.Fatalf("--yes public share: %v", err)
	}
}

func TestShareNeedsTheTracesWriteScope(t *testing.T) {
	env := newShareEnv(t)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeProfileRead, account.ScopeMCPTokenCreate)
	stdout, _, err := runShareCommand(t, "--cwd", env.projectDir, "--json", "--log-path", env.logPath)
	if !errors.Is(err, account.ErrTracesWriteScope) || len(srv.requests) != 0 {
		t.Fatalf("err = %v, requests = %v", err, srv.requests)
	}
	if !strings.Contains(stdout, `"ok":false`) || !strings.Contains(stdout, "beacon login") {
		t.Fatalf("json error = %s", stdout)
	}

	// An API key stands in for the sign-in.
	shareGetenv = func(name string) string {
		if name == account.APIKeyEnv {
			return "bcn_api_test_key"
		}
		return ""
	}
	t.Setenv(account.BaseURLEnv, srv.server.URL)
	if _, _, err := runShareCommand(t, "--cwd", env.projectDir, "--log-path", env.logPath); err != nil {
		t.Fatalf("share with API key: %v", err)
	}
	if !srv.auth["Bearer bcn_api_test_key"] {
		t.Fatalf("auth = %v", srv.auth)
	}
}

func TestShareRefreshParsesExternalIDs(t *testing.T) {
	cases := map[string]struct {
		harness, session string
		ok               bool
	}{
		"claude_code:abc-123":        {handoff.HarnessClaude, "abc-123", true},
		"codex:rollout:1":            {handoff.HarnessCodex, "rollout:1", true},
		"cursor:sha256-0123456789ab": {"", "", false},
		"abc-123":                    {"", "", false},
		"nope:abc":                   {"", "", false},
	}
	for in, want := range cases {
		h, s, ok := parseShareExternalID(in)
		if ok != want.ok || h != want.harness || s != want.session {
			t.Errorf("parseShareExternalID(%q) = %q %q %v, want %+v", in, h, s, ok, want)
		}
	}
	if got := messagesAfter([]asymptoteobserve.ShareMessageV1{{ID: "a"}, {ID: "b"}, {ID: "c"}}, "b", 2); len(got) != 2 || got[0].ID != "b" {
		t.Fatalf("messagesAfter should resend the last uploaded message: %+v", got)
	}
	// A call uploaded before its result arrived is re-sent so the completion's command and diff
	// reach the server.
	call := func(id, callID string) asymptoteobserve.ShareMessageV1 {
		return asymptoteobserve.ShareMessageV1{ID: id, Parts: []asymptoteobserve.SharePartV1{{Type: asymptoteobserve.SharePartToolCall, Content: &asymptoteobserve.ShareToolCallContent{CallID: callID}}}}
	}
	result := func(id, callID string) asymptoteobserve.ShareMessageV1 {
		return asymptoteobserve.ShareMessageV1{ID: id, Parts: []asymptoteobserve.SharePartV1{{Type: asymptoteobserve.SharePartToolResult, Content: &asymptoteobserve.ShareToolResultContent{CallID: callID}}}}
	}
	msgs := []asymptoteobserve.ShareMessageV1{call("c1", "t1"), result("r1", "t1"), call("c2", "t2"), {ID: "text"}, result("r2", "t2"), {ID: "later"}}
	if got := messagesAfter(msgs, "text", 0); len(got) != 4 || got[0].ID != "c2" {
		t.Fatalf("open call not re-sent: %+v", got)
	}
	if got := messagesAfter(msgs, "r2", 0); len(got) != 2 || got[0].ID != "r2" {
		t.Fatalf("resolved calls should not be re-sent: %+v", got)
	}
	if got := messagesAfter([]asymptoteobserve.ShareMessageV1{{ID: "a"}, {ID: "b"}}, "zzz", 9); len(got) != 2 {
		t.Fatalf("unknown last id should resend everything: %+v", got)
	}
}

func TestShareLeavesALocalGitRemoteOut(t *testing.T) {
	env := newShareEnv(t)
	for _, remote := range []string{filepath.Join(env.home, "mirrors", "app.git"), "file://" + filepath.Join(env.home, "mirrors", "app.git")} {
		shareGitRemote = func(string) string { return remote }
		stdout, _, err := runShareCommand(t, "--cwd", env.projectDir, "--print", "--log-path", env.logPath)
		if err != nil {
			t.Fatalf("share --print: %v", err)
		}
		var payload sharePayload
		if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Trace.GitRemoteURL != "" || strings.Contains(stdout, env.home) {
			t.Fatalf("remote %q leaked into the payload: %+v", remote, payload.Trace)
		}
	}
	shareGitRemote = func(string) string { return "https://tok@github.com/acme/app.git" }
	stdout, _, err := runShareCommand(t, "--cwd", env.projectDir, "--print", "--log-path", env.logPath)
	if err != nil || !strings.Contains(stdout, `"git_remote_url": "https://github.com/acme/app.git"`) {
		t.Fatalf("network remote: err=%v\n%s", err, stdout)
	}
}

func TestShareRefreshRefusesToDuplicateFromAnotherSource(t *testing.T) {
	env := newShareEnv(t)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)
	if _, stderr, err := runShareCommand(t, "--cwd", env.projectDir, "--log-path", env.logPath); err != nil {
		t.Fatalf("share: %v\n%s", err, stderr)
	}

	// The store loses the session (its transcript was deleted); the runtime log still has it, as
	// hook events whose ids differ from the store's.
	stubHandoffSources(t, stubHandoffSource{
		harness: handoff.HarnessClaude,
		sessions: []handoff.Session{{
			Harness: handoff.HarnessClaude, ID: shareTestSession, Directory: env.projectDir, UpdatedAt: time.Now(),
		}},
		eventsErr: handoff.ErrNotFound,
	})
	for _, event := range shareFixtureEvents(env.projectDir) {
		event.Harness.CollectionMethod = schema.CollectionMethodHook
		if _, err := writer.AppendEvent(event, writer.Options{Path: env.logPath, UserMode: true}); err != nil {
			t.Fatal(err)
		}
	}
	_, _, err := runShareCommand(t, "refresh", "claude_code:"+shareTestSession, "--log-path", env.logPath)
	if err == nil || !strings.Contains(err.Error(), "duplicate every message") {
		t.Fatalf("refresh err = %v", err)
	}
	if len(srv.messages) != 4 {
		t.Fatalf("server holds %d messages after a refused refresh", len(srv.messages))
	}
}

func TestShareRefreshKeepsATitleSetEarlier(t *testing.T) {
	env := newShareEnv(t)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)
	if _, stderr, err := runShareCommand(t, "--cwd", env.projectDir, "--title", "Login fix", "--log-path", env.logPath); err != nil {
		t.Fatalf("share: %v\n%s", err, stderr)
	}
	if _, _, err := runShareCommand(t, "refresh", "claude_code:"+shareTestSession, "--log-path", env.logPath); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if _, _, err := runShareCommand(t, "--cwd", env.projectDir, "--log-path", env.logPath); err != nil {
		t.Fatalf("re-share: %v", err)
	}
	if srv.trace.Title != "Login fix" {
		t.Fatalf("title = %q, want the one set with --title", srv.trace.Title)
	}
	if _, _, err := runShareCommand(t, "--cwd", env.projectDir, "--title", "Renamed", "--log-path", env.logPath); err != nil {
		t.Fatal(err)
	}
	if srv.trace.Title != "Renamed" {
		t.Fatalf("an explicit --title did not apply: %q", srv.trace.Title)
	}
}

// pathMatchingSource is a store that, like the real ones, finds a session's events only by the
// store path it listed the session with.
type pathMatchingSource struct{ stubHandoffSource }

func (s pathMatchingSource) Events(session handoff.Session) ([]schema.Event, error) {
	if len(s.sessions) == 0 || session.SourcePath != s.sessions[0].SourcePath {
		return nil, handoff.ErrNotFound
	}
	return s.events, nil
}

func TestShareAlignSwitchesFromTheLogToTheStore(t *testing.T) {
	env := newShareEnv(t)
	storeSession := handoff.Session{Harness: handoff.HarnessClaude, ID: shareTestSession, Directory: env.projectDir, SourcePath: filepath.Join(env.home, "store", shareTestSession+".jsonl"), UpdatedAt: time.Now()}
	stubHandoffSources(t, pathMatchingSource{stubHandoffSource{harness: handoff.HarnessClaude, sessions: []handoff.Session{storeSession}, events: shareFixtureEvents(env.projectDir)}})
	shareOpts = shareOptions{logPath: env.logPath}

	stored, err := buildSharePayload(shareSubject{session: storeSession})
	if err != nil {
		t.Fatal(err)
	}
	var logEvents []schema.Event
	for _, event := range shareFixtureEvents(env.projectDir) {
		event.Harness.CollectionMethod = schema.CollectionMethodHook
		logEvents = append(logEvents, event)
	}
	// Found in the log: no store path.
	logSubject := shareSubject{session: handoff.Session{Harness: handoff.HarnessClaude, ID: shareTestSession, Directory: env.projectDir}, fromLog: true, logEvents: logEvents}
	logPayload, err := buildSharePayload(logSubject)
	if err != nil {
		t.Fatal(err)
	}
	state := &asymptoteobserve.ShareTraceStateV1{LastMessageID: stored.Messages[len(stored.Messages)-1].ID}
	subject, payload, err := alignShareSource(logSubject, logPayload, state)
	if err != nil {
		t.Fatalf("align: %v", err)
	}
	if subject.fromLog || !hasShareMessage(payload.Messages, state.LastMessageID) {
		t.Fatalf("did not switch to the store copy: fromLog=%v", subject.fromLog)
	}
}
