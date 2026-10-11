package cmd

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/schema"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/writer"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/handoff"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve/activesession"
)

// shareCurrentEnv adds a second, older Claude Code session and a Gemini CLI session (log only) in
// the project directory, so each resolution step can be told apart from "most recent".
func shareCurrentEnv(t *testing.T) *shareEnv {
	t.Helper()
	env := newShareEnv(t)
	recordPath := filepath.Join(env.home, "active.json")
	prev := shareActiveSessionsPath
	shareActiveSessionsPath = func() string { return recordPath }
	t.Cleanup(func() { shareActiveSessionsPath = prev })
	gem := schema.NewEvent(schema.NewEventOptions{Action: "prompt.submitted", Category: "prompt", Harness: schema.HarnessInfo{Name: "gemini_cli", CollectionMethod: schema.CollectionMethodHook}})
	gem.Timestamp = schema.FormatTimestamp(time.Now().Add(-time.Hour))
	gem.Session = &schema.SessionInfo{ID: "gem-session-1", WorkingDirectory: env.projectDir}
	gem.Prompt = &schema.PromptInfo{Text: "Add a flag"}
	if _, err := writer.AppendEvent(gem, writer.Options{Path: env.logPath, UserMode: true}); err != nil {
		t.Fatal(err)
	}
	return env
}

func sharePrintedExternalID(t *testing.T, stdout string) string {
	t.Helper()
	var payload sharePayload
	if err := json.Unmarshal([]byte(stdout), &payload); err != nil {
		t.Fatalf("payload is not JSON: %v\n%s", err, stdout)
	}
	return payload.ExternalID
}

func TestShareCurrentPrefersTheSessionEnvironment(t *testing.T) {
	env := shareCurrentEnv(t)
	t.Chdir(env.projectDir)
	shareGetenv = func(key string) string {
		switch key {
		case shareSessionEnv:
			return "gem-session-1"
		case shareHarnessEnv:
			return "gemini_cli"
		}
		return ""
	}
	stdout, _, err := runShareCommand(t, "--print", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if got := sharePrintedExternalID(t, stdout); got != "gemini_cli:gem-session-1" {
		t.Fatalf("external id = %q, want the env session", got)
	}

	// --harness naming another runtime ignores inherited variables.
	stdout, _, err = runShareCommand(t, "--current", "--harness", "claude", "--print", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("share --harness claude: %v", err)
	}
	if got := sharePrintedExternalID(t, stdout); got != "claude_code:"+shareTestSession {
		t.Fatalf("external id = %q, want the claude session", got)
	}

	// An env id that cannot be found is an error, never some other session.
	shareGetenv = func(key string) string {
		switch key {
		case shareSessionEnv:
			return "missing-session"
		case shareHarnessEnv:
			return "gemini_cli"
		}
		return ""
	}
	if _, _, err := runShareCommand(t, "--current", "--print", "--log-path", env.logPath); err == nil || !strings.Contains(err.Error(), "BEACON_SESSION_ID=missing-session") {
		t.Fatalf("missing env session: err = %v", err)
	}
}

func TestShareCurrentRefusesAnUnusableHarnessVariable(t *testing.T) {
	env := shareCurrentEnv(t)
	t.Chdir(env.projectDir)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)
	for _, tc := range []struct{ harness, want string }{
		{"kimi_kode", `BEACON_HARNESS="kimi_kode"`},
		{"", "BEACON_HARNESS is not"},
	} {
		shareGetenv = func(key string) string {
			switch key {
			case shareSessionEnv:
				return "gem-session-1"
			case shareHarnessEnv:
				return tc.harness
			}
			return ""
		}
		_, _, err := runShareCommand(t, "--log-path", env.logPath)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("BEACON_HARNESS=%q: err = %v, want %q", tc.harness, err, tc.want)
		}
	}
	if len(srv.requests) != 0 {
		t.Fatalf("requests = %v", srv.requests)
	}
	// --harness naming another valid runtime passes over the variables on purpose.
	shareGetenv = func(key string) string {
		switch key {
		case shareSessionEnv:
			return "gem-session-1"
		case shareHarnessEnv:
			return "gemini_cli"
		}
		return ""
	}
	stdout, _, err := runShareCommand(t, "--harness", "claude", "--print", "--log-path", env.logPath)
	if err != nil || sharePrintedExternalID(t, stdout) != "claude_code:"+shareTestSession {
		t.Fatalf("--harness claude: err = %v\n%s", err, stdout)
	}
}

func TestShareCurrentUsesTheActiveSessionRecord(t *testing.T) {
	env := shareCurrentEnv(t)
	t.Chdir(env.projectDir)
	// The Claude session is the most recent; the hook last saw Gemini here.
	if err := activesession.Record(shareActiveSessionsPath(), "gemini_cli", "gem-session-1", env.projectDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runShareCommand(t, "--current", "--print", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("share --current: %v", err)
	}
	if got := sharePrintedExternalID(t, stdout); got != "gemini_cli:gem-session-1" {
		t.Fatalf("external id = %q, want the active session", got)
	}
	// A --harness hint passes over another runtime's entry.
	stdout, _, err = runShareCommand(t, "--harness", "claude_code", "--print", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("share --harness: %v", err)
	}
	if got := sharePrintedExternalID(t, stdout); got != "claude_code:"+shareTestSession {
		t.Fatalf("external id = %q", got)
	}
	// A stale entry is ignored.
	shareNow = func() time.Time { return time.Now().Add(48 * time.Hour) }
	t.Cleanup(func() { shareNow = time.Now })
	stdout, _, err = runShareCommand(t, "--print", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if got := sharePrintedExternalID(t, stdout); got != "claude_code:"+shareTestSession {
		t.Fatalf("stale record used: %q", got)
	}
}

func TestShareCurrentNamesCandidatesWhenNothingRanHere(t *testing.T) {
	env := shareCurrentEnv(t)
	empty := t.TempDir()
	t.Chdir(empty)
	_, _, err := runShareCommand(t, "--current", "--print", "--log-path", env.logPath)
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"no agent session found", shareTestSession, "gem-session-1", "--session"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	if _, _, err := runShareCommand(t, "--current", "--session", shareTestSession, "--print"); err == nil {
		t.Fatal("--current with --session accepted")
	}
}

func TestShareCurrentPassesOverAnOlderActiveEntry(t *testing.T) {
	env := newShareEnv(t)
	t.Chdir(env.projectDir)
	recordPath := filepath.Join(env.home, "active.json")
	prev := shareActiveSessionsPath
	shareActiveSessionsPath = func() string { return recordPath }
	t.Cleanup(func() { shareActiveSessionsPath = prev })
	hourAgo := time.Now().Add(-time.Hour)
	stubHandoffSources(t, stubHandoffSource{
		harness: handoff.HarnessClaude,
		sessions: []handoff.Session{{
			Harness: handoff.HarnessClaude, ID: shareTestSession, Directory: env.projectDir, UpdatedAt: hourAgo,
		}},
		events: shareFixtureEvents(env.projectDir),
	})
	// The hook saw Claude Code here an hour ago; Copilot CLI, which only exports OTLP and never
	// writes the record, has worked here since.
	if err := activesession.Record(recordPath, handoff.HarnessClaude, shareTestSession, env.projectDir, hourAgo); err != nil {
		t.Fatal(err)
	}
	copilot := schema.NewEvent(schema.NewEventOptions{Action: "prompt.submitted", Category: "prompt", Harness: schema.HarnessInfo{Name: handoff.HarnessCopilot, CollectionMethod: schema.CollectionMethodOTLP}})
	copilot.Timestamp = schema.FormatTimestamp(time.Now().Add(-5 * time.Minute))
	copilot.Session = &schema.SessionInfo{ID: "copilot-session-1", WorkingDirectory: env.projectDir}
	copilot.Prompt = &schema.PromptInfo{Text: "Bump the version"}
	if _, err := writer.AppendEvent(copilot, writer.Options{Path: env.logPath, UserMode: true}); err != nil {
		t.Fatal(err)
	}
	stdout, _, err := runShareCommand(t, "--print", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if got := sharePrintedExternalID(t, stdout); got != handoff.HarnessCopilot+":copilot-session-1" {
		t.Fatalf("external id = %q, want the newer Copilot session", got)
	}

	// Once the hook sees Claude Code again, its entry is the newest and is chosen.
	if err := activesession.Record(recordPath, handoff.HarnessClaude, shareTestSession, env.projectDir, time.Now()); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = runShareCommand(t, "--json", "--print", "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if got := sharePrintedExternalID(t, stdout); got != "claude_code:"+shareTestSession {
		t.Fatalf("external id = %q, want the active Claude Code session", got)
	}
}
