//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/sessionfs"
)

// A system backfill reads the console user's home as root, so it confines every store read to that
// home and to files that user owns; a user backfill reads the user's own home unconfined.
func TestSystemEndpointBackfillConfinesReadsToTheConsoleUsersHome(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(home, "mine.jsonl"), []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "theirs.jsonl")
	if err := os.WriteFile(secret, []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(home, "planted.jsonl")
	if err := os.Symlink(secret, planted); err != nil {
		t.Fatal(err)
	}

	var mine, theirs string
	var plantedErr error
	stubBackfill(t, 1<<20, 1<<20, endpointBackfillRunner{Name: "Probe", Sync: "beacon endpoint probe sync", Run: func(r endpointBackfillRun) (int, error) {
		data, _ := sessionfs.ReadFile(filepath.Join(home, "mine.jsonl"))
		mine = string(data)
		data, plantedErr = sessionfs.ReadFile(planted)
		theirs = string(data)
		return 0, nil
	}})
	stubConsoleUser(t, consoleUserInfo{Username: "alice", HomeDir: home}, true, nil)

	var out strings.Builder
	reportEndpointBackfill(&out, runEndpointBackfill(filepath.Join(t.TempDir(), "runtime.jsonl"), false))
	if mine != "mine" {
		t.Fatalf("system backfill could not read the console user's own file: %q", mine)
	}
	if theirs != "" || !os.IsNotExist(plantedErr) {
		t.Fatalf("system backfill read through a link out of the home: %q, %v", theirs, plantedErr)
	}
	if !strings.Contains(out.String(), "Skipped 1 session store path(s)") || !strings.Contains(out.String(), planted) {
		t.Fatalf("report does not name the skipped path:\n%s", out.String())
	}

	// The confinement ends with the system sweep: a user backfill follows the user's own links.
	theirs = ""
	out.Reset()
	reportEndpointBackfill(&out, runEndpointBackfill(filepath.Join(t.TempDir(), "runtime.jsonl"), true))
	if theirs != "theirs" {
		t.Fatalf("user backfill was confined: %q, %v", theirs, plantedErr)
	}
	if strings.Contains(out.String(), "Skipped") {
		t.Fatalf("user backfill reported refusals:\n%s", out.String())
	}
}
