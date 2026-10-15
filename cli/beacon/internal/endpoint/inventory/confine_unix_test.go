//go:build unix

package inventory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/sessionfs"
)

// The system inventory job scans the console user's home as root under a sessionfs confinement.
// What that user plants there -- a symlink to a root-only file, a FIFO -- must read as absent
// rather than be read with root's privileges or hang the job.
func TestConfinedScanRefusesPlantedLinksAndFIFOs(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the home a different owner")
	}
	const uid = 4242
	home := t.TempDir()
	secret := filepath.Join(t.TempDir(), "root-only")
	if err := os.WriteFile(secret, []byte(`{"mcpServers":{"leak":{"command":"TOPSECRET"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".claude", ".codex", ".cursor"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(filepath.Join(home, ".claude", "settings.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(home, ".cursor", "mcp.json")); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(home, ".codex", "config.toml")
	if err := os.WriteFile(owned, []byte("model = \"x\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := filepath.Walk(home, func(path string, _ os.FileInfo, _ error) error { return os.Lchown(path, uid, uid) }); err != nil {
		t.Fatal(err)
	}

	confined, err := sessionfs.Confine(home, uid, sessionfs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer confined.Release()

	done := make(chan Result, 1)
	go func() {
		done <- Scan(Options{HomeDir: home, SkipProjectScope: true, Runtimes: []string{"claude_code", "codex_cli", "cursor"}, IncludeContents: true})
	}()
	var result Result
	select {
	case result = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("confined scan hung on a planted FIFO")
	}
	for _, config := range result.Configs {
		if blob, _ := json.Marshal(config); strings.Contains(string(blob), "TOPSECRET") {
			t.Fatalf("confined scan read a symlinked root-only file: %+v", config)
		}
		if config.Readable && config.PathHash == hashString(filepath.Join(home, ".cursor", "mcp.json")) {
			t.Fatalf("confined scan read through a symlink out of the home: %+v", config)
		}
	}
	if len(result.MCPServers) != 0 {
		t.Fatalf("confined scan parsed MCP servers from a symlinked root-only file: %+v", result.MCPServers)
	}
	var sawOwned bool
	for _, config := range result.Configs {
		if config.PathHash == hashString(owned) && config.Readable {
			sawOwned = true
		}
	}
	if !sawOwned {
		t.Fatal("confined scan did not read the user's own config")
	}
}

func TestReadFilePathCapsSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(path, make([]byte, maxInventoryFileBytes+1), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readFilePath(path); err == nil {
		t.Fatal("readFilePath read past the cap")
	}
}
