package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve/activesession"
)

func TestSessionStartRecordsTheActiveSession(t *testing.T) {
	setupHookConfigDirs(t)
	platformFlag = "claude"
	t.Cleanup(func() { platformFlag = "claude" })
	dir := t.TempDir()
	t.Setenv("BEACON_ENDPOINT_MODE", "1")
	t.Setenv("BEACON_ENDPOINT_LOG", filepath.Join(dir, "runtime.jsonl"))
	record := filepath.Join(dir, "endpoint", activesession.FileName)
	t.Setenv(activesession.PathEnv, record)

	runHookWithInput(t, runSessionStart, map[string]interface{}{
		"hook_event_name": "SessionStart",
		"session_id":      "11111111-2222-3333-4444-555555555555",
		"cwd":             "/work/project",
	})
	got, ok := activesession.Lookup(record, "claude_code", "/work/project", 0, time.Now())
	if !ok || got.SessionID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("active session = %+v, %v", got, ok)
	}
}

func TestSessionStartExportsTheSessionToClaudeEnvFile(t *testing.T) {
	setupHookConfigDirs(t)
	platformFlag = "claude"
	t.Cleanup(func() { platformFlag = "claude" })
	dir := t.TempDir()
	t.Setenv("BEACON_ENDPOINT_MODE", "1")
	t.Setenv("BEACON_ENDPOINT_LOG", filepath.Join(dir, "runtime.jsonl"))
	envFile := filepath.Join(dir, "claude-env.sh")
	if err := os.WriteFile(envFile, []byte("export NODE_ENV=production\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLAUDE_ENV_FILE", envFile)

	runHookWithInput(t, runSessionStart, map[string]interface{}{
		"hook_event_name": "SessionStart",
		"session_id":      "abc-123",
		"cwd":             "/work/project",
	})
	data, _ := os.ReadFile(envFile)
	want := "export NODE_ENV=production\nexport BEACON_SESSION_ID=abc-123\nexport BEACON_HARNESS=claude_code\n"
	if string(data) != want {
		t.Fatalf("env file = %q, want %q", data, want)
	}

	// A session id that is not a plain identifier is never written into shell code.
	runHookWithInput(t, runSessionStart, map[string]interface{}{
		"hook_event_name": "SessionStart",
		"session_id":      "x; rm -rf ~",
		"cwd":             "/work/project",
	})
	if after, _ := os.ReadFile(envFile); string(after) != want {
		t.Fatalf("unsafe id written: %q", after)
	}
}

func TestSessionStartLeavesClaudeEnvFileAloneOnOtherRuntimes(t *testing.T) {
	setupHookConfigDirs(t)
	platformFlag = "qwen"
	t.Cleanup(func() { platformFlag = "claude" })
	dir := t.TempDir()
	t.Setenv("BEACON_ENDPOINT_MODE", "1")
	t.Setenv("BEACON_ENDPOINT_LOG", filepath.Join(dir, "runtime.jsonl"))
	envFile := filepath.Join(dir, "claude-env.sh")
	t.Setenv("CLAUDE_ENV_FILE", envFile)

	runHookWithInput(t, runSessionStart, map[string]interface{}{
		"hook_event_name": "SessionStart",
		"session_id":      "q-1",
		"cwd":             "/work/project",
	})
	if _, err := os.Stat(envFile); !os.IsNotExist(err) {
		t.Fatalf("env file written on qwen: %v", err)
	}
}
