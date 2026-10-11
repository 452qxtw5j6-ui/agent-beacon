package cmd

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/schema"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/writer"
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
		if key == shareSessionEnv {
			return "missing-session"
		}
		return ""
	}
	if _, _, err := runShareCommand(t, "--current", "--print", "--log-path", env.logPath); err == nil || !strings.Contains(err.Error(), "BEACON_SESSION_ID=missing-session") {
		t.Fatalf("missing env session: err = %v", err)
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
