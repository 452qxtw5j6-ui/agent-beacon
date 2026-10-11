//go:build !windows

package claudesession

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/sessionfs"
)

// A system backfill runs this collector as root over the console user's home. Whatever that user
// links into their store must not be read: not a transcript linked from another home, not a
// project directory linked away, and not a FIFO that would block the install.
func TestConfinedCollectSkipsWhatTheConsoleUserPlanted(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	projects := filepath.Join(home, ".claude", "projects")
	writeFile(t, filepath.Join(projects, "-tmp-repo", "mine.jsonl"), userLine("mine", "u1", "my own prompt")+"\n")
	victim := filepath.Join(outside, ".claude", "projects", "-victim")
	writeFile(t, filepath.Join(victim, "theirs.jsonl"), userLine("theirs", "v1", "someone else's secret prompt")+"\n")

	if err := os.Symlink(victim, filepath.Join(projects, "-victim")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(victim, "theirs.jsonl"), filepath.Join(projects, "-tmp-repo", "planted.jsonl")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(projects, "-tmp-repo", "fifo.jsonl"), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	confined, err := sessionfs.Confine(home, os.Getuid(), sessionfs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(confined.Release)

	state := t.TempDir()
	logPath := filepath.Join(state, "runtime.jsonl")
	done := make(chan error, 1)
	go func() {
		_, err := CollectOnce(CollectOptions{ProjectsDir: projects, StatePath: filepath.Join(state, "claude.json"), LogPath: logPath, Write: true, UserMode: true})
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CollectOnce: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("collecting hung on a planted FIFO")
	}

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "my own prompt") {
		t.Fatal("the console user's own transcript was not collected")
	}
	if strings.Contains(string(data), "secret prompt") {
		t.Fatal("a transcript linked from outside the home was read")
	}
	if n, _ := confined.Refused(); n == 0 {
		t.Fatal("no refusal was recorded for the planted paths")
	}
}

// A store directory that is itself a link out of the home, ~/.claude -> /root/.claude, reads as no
// store at all.
func TestConfinedCollectReadsNothingThroughALinkedStore(t *testing.T) {
	home, outside := t.TempDir(), t.TempDir()
	writeFile(t, filepath.Join(outside, ".claude", "projects", "-root", "root.jsonl"), userLine("root", "r1", "root's prompt")+"\n")
	if err := os.Symlink(filepath.Join(outside, ".claude"), filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	confined, err := sessionfs.Confine(home, os.Getuid(), sessionfs.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(confined.Release)

	state := t.TempDir()
	logPath := filepath.Join(state, "runtime.jsonl")
	summary, err := CollectOnce(CollectOptions{ProjectsDir: filepath.Join(home, ".claude", "projects"), StatePath: filepath.Join(state, "claude.json"), LogPath: logPath, Write: true, UserMode: true})
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if summary.EventsEmitted != 0 {
		t.Fatalf("emitted %d events from a store linked out of the home", summary.EventsEmitted)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("the runtime log was written: %v", err)
	}
}
