//go:build !windows

package logging

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The hook adapter appends to a log a system-mode collector created while running elevated, so the
// file has to stay writable by both. A restrictive umask on whichever process creates it first
// would otherwise produce a log the other cannot write, and telemetry would stop while status kept
// reporting healthy.
//
// Unix-only because umask is. On Windows the same property is an ACL on the system log directory
// rather than a file mode, and there it is a real gap rather than a non-issue.

func TestEndpointEventCreatesSharedRuntimeFilesDespiteUmask(t *testing.T) {
	oldUmask := syscall.Umask(0022)
	t.Cleanup(func() {
		syscall.Umask(oldUmask)
	})

	logPath := filepath.Join(t.TempDir(), "runtime.jsonl")
	t.Setenv("BEACON_ENDPOINT_LOG", logPath)

	logger := NewLoggerForPlatform("agent-thought", "cursor")
	if err := logger.EndpointEvent("agent.reasoning", "session", "info", "Agent reasoning captured", nil); err != nil {
		t.Fatalf("EndpointEvent returned error: %v", err)
	}

	for _, target := range []string{logPath, logPath + ".lock"} {
		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf("stat %s: %v", target, err)
		}
		if got := info.Mode().Perm(); got != endpointRuntimeFileMode {
			t.Fatalf("%s mode = %o, want %o", target, got, endpointRuntimeFileMode)
		}
	}
}

// A hook runs as the person at the keyboard and may not rename or delete anything in a system log
// directory -- root-owned 0755 here, and on Windows an ACL that withholds exactly those rights so a
// user cannot redirect a SYSTEM write. When the log is over its size limit the hook must append
// anyway and leave rotation to the collector, rather than drop the event.
func TestAppendEndpointJSONLAppendsWhenRotationIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the refusal cannot be reproduced")
	}
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "runtime.jsonl")
	if err := os.WriteFile(path, []byte("{\"existing\":true}\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".lock", nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	if err := appendEndpointJSONL(path, []byte("{\"next\":true}\n"), 8, defaultEndpointRotateArchives); err != nil {
		t.Fatalf("append with rotation refused: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\"existing\":true}\n{\"next\":true}\n" {
		t.Fatalf("log after a refused rotation = %q, want the new line appended", data)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("an archive appeared although rotation was refused: %v", err)
	}
}
