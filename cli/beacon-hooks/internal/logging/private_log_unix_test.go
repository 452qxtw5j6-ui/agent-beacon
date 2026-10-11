//go:build !windows

package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertEndpointPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", path, got, want)
	}
}

// The default user-mode log (BEACON_ENDPOINT_MODE with no explicit path) lives in the user's home
// and is written only by that user's processes, so the hook creates it, its lock and its
// directories private. It used to create 0666 files in 0755 directories.
func TestUserModeEndpointLogIsPrivate(t *testing.T) {
	isolateHookHome(t)
	home := os.Getenv("HOME")
	t.Setenv("BEACON_ENDPOINT_LOG", "")
	t.Setenv("BEACON_CLOUD_LOG_PATH", "")
	t.Setenv("BEACON_LOG_PATH", "")
	t.Setenv("BEACON_RUNTIME_LOG", "")
	t.Setenv("BEACON_ENDPOINT_MODE", "1")
	logPath := endpointLogPath()
	if !strings.HasPrefix(logPath, home) {
		t.Fatalf("default endpoint log %s is not under the test home %s", logPath, home)
	}

	logger := NewLoggerForPlatform("agent-thought", "cursor")
	if err := logger.EndpointEvent("agent.reasoning", "session", "info", "Agent reasoning captured", nil); err != nil {
		t.Fatal(err)
	}
	assertEndpointPerm(t, logPath, 0o600)
	assertEndpointPerm(t, logPath+".lock", 0o600)
	for _, dir := range []string{
		filepath.Join(home, ".beacon", "endpoint"),
		filepath.Join(home, ".beacon", "endpoint", "logs"),
	} {
		assertEndpointPerm(t, dir, 0o700)
	}
}

// A log an older release left world-writable is tightened on the next append, and rotation keeps
// archives private, including ones rotated before the change.
func TestUserModeEndpointLogIsTightenedAndRotatesPrivately(t *testing.T) {
	isolateHookHome(t)
	home := os.Getenv("HOME")
	logPath := filepath.Join(home, ".beacon", "endpoint", "logs", "runtime.jsonl")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{logPath, logPath + ".lock", logPath + ".1"} {
		if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0o666); err != nil {
			t.Fatal(err)
		}
	}

	line := []byte(`{"message":"` + strings.Repeat("x", 64) + `"}` + "\n")
	if err := appendEndpointJSONL(logPath, line, 32, defaultEndpointRotateArchives); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(logPath + ".2"); err != nil {
		t.Fatalf("expected the log to rotate: %v", err)
	}
	for _, target := range []string{logPath, logPath + ".lock", logPath + ".1", logPath + ".2"} {
		assertEndpointPerm(t, target, 0o600)
	}
}

// System mode is unchanged: a log outside the user's home (the shared /var/log/beacon-agent log in
// practice) keeps the shared mode so every user's hooks can append to it.
func TestSharedEndpointLogKeepsTheSharedMode(t *testing.T) {
	isolateHookHome(t)
	logPath := filepath.Join(t.TempDir(), "beacon-agent", "runtime.jsonl")
	t.Setenv("BEACON_ENDPOINT_LOG", logPath)

	logger := NewLoggerForPlatform("agent-thought", "cursor")
	if err := logger.EndpointEvent("agent.reasoning", "session", "info", "Agent reasoning captured", nil); err != nil {
		t.Fatal(err)
	}
	assertEndpointPerm(t, logPath, 0o666)
	assertEndpointPerm(t, logPath+".lock", 0o666)
}
