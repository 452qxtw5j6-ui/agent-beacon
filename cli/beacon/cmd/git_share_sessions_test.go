package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/schema"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/gitlink"
)

func writeSharedEvent(t *testing.T, logPath, harness, session, url string) {
	t.Helper()
	event := schema.NewEvent(schema.NewEventOptions{Action: SessionSharedAction, Category: "session", Harness: schema.HarnessInfo{Name: harness}})
	event.Session = &schema.SessionInfo{ID: session}
	event.Raw = map[string]interface{}{"shared_url": url}
	line, _ := json.Marshal(event)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
}

func TestGitHookPostCommitWritesAKnownShareURL(t *testing.T) {
	root := gitCommandRepo(t)
	top := mustGit(t, root, "rev-parse", "--show-toplevel")
	logPath := filepath.Join(t.TempDir(), "runtime.jsonl")
	for _, f := range []string{"x.go", "y.go"} {
		if err := os.WriteFile(filepath.Join(root, f), []byte("package x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeRuntimeEvent(t, logPath, top, "cur-1", "x.go")
	writeRuntimeEvent(t, logPath, top, "cur-2", "y.go")
	writeSharedEvent(t, logPath, "cursor", "cur-1", "https://beacon.sh/s/abc123")
	writeSharedEvent(t, logPath, "cursor", "cur-2", "https://evil.example/s/abc123")
	mustGit(t, root, "add", "-A")
	mustGit(t, root, "commit", "-q", "-m", "x")
	if out, err := runGit(t, "hook", "post-commit", "--cwd", root, "--log-path", logPath); err != nil || out != "" {
		t.Fatalf("hook: %v %q", err, out)
	}
	note := mustGit(t, root, "notes", "--ref="+gitlink.NotesRef, "show", "HEAD")
	if !strings.Contains(note, "beacon:cursor/cur-1 https://beacon.sh/s/abc123") || !strings.Contains(note, "beacon:cursor/cur-2") || strings.Contains(note, "evil.example") {
		t.Fatalf("note %q", note)
	}
	out, err := runGit(t, "notes", "--cwd", root, "--json")
	if err != nil || !strings.Contains(out, `"url": "https://beacon.sh/s/abc123"`) {
		t.Fatalf("notes --json: %v\n%s", err, out)
	}
	out, _ = runGit(t, "notes", "--cwd", root)
	if !strings.Contains(out, "cursor/cur-1  https://beacon.sh/s/abc123") {
		t.Fatalf("notes:\n%s", out)
	}
}

func TestGitPrePushSharesLinkedSessions(t *testing.T) {
	root, remote := gitCommandTeam(t)
	env := newShareEnv(t)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)
	prevOpts := shareOpts
	shareOpts = shareOptions{logPath: env.logPath}
	t.Cleanup(func() { shareOpts = prevOpts })

	old := mustGit(t, root, "rev-parse", "HEAD")
	mustGit(t, root, "commit", "-q", "--allow-empty", "-m", "agent work")
	sha := mustGit(t, root, "rev-parse", "HEAD")
	mustGit(t, root, "notes", "--ref="+gitlink.NotesRef, "add", "-m", "beacon:claude_code/"+shareTestSession+"\nbeacon:cursor/someone-else", sha)
	if out, err := runGit(t, "setup", "--cwd", root, "--share-sessions"); err != nil || !strings.Contains(out, "shares the agent sessions linked") {
		t.Fatalf("setup: %v\n%s", err, out)
	}
	if out, _ := runGit(t, "status", "--cwd", root); !strings.Contains(out, "sessions    on: pushes share linked sessions to beacon.sh (direct)") {
		t.Fatalf("status:\n%s", out)
	}

	stdin := "refs/heads/main " + sha + " refs/heads/main " + old + "\n"
	var stderr bytes.Buffer
	rootCmd.SetIn(strings.NewReader(stdin))
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	if _, err := runGitStderr(t, &stderr, "hook", "pre-push", "--cwd", root, "origin", remote); err != nil {
		t.Fatalf("pre-push: %v", err)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr %q", stderr.String())
	}
	if len(srv.messages) != 4 {
		t.Fatalf("server messages = %d", len(srv.messages))
	}
	want := "beacon:claude_code/" + shareTestSession + " https://beacon.sh/s/k3xabc\nbeacon:cursor/someone-else"
	if note := mustGit(t, root, "notes", "--ref="+gitlink.NotesRef, "show", sha); note != want {
		t.Fatalf("local note %q", note)
	}
	if note := mustGit(t, remote, "notes", "--ref="+gitlink.NotesRef, "show", sha); note != want {
		t.Fatalf("remote note %q", note)
	}
	if urls := localShareURLs(env.logPath); urls["claude_code/"+shareTestSession] != "https://beacon.sh/s/k3xabc" {
		t.Fatalf("session.shared not recorded: %v", urls)
	}

	// A second push has nothing left to share and makes no share request.
	before := len(srv.requests)
	rootCmd.SetIn(strings.NewReader(stdin))
	if _, err := runGitStderr(t, &stderr, "hook", "pre-push", "--cwd", root, "origin", remote); err != nil || stderr.Len() != 0 {
		t.Fatalf("second pre-push: %v %q", err, stderr.String())
	}
	if len(srv.requests) != before {
		t.Fatalf("second push made share requests: %v", srv.requests[before:])
	}
}

func TestGitPrePushWithoutCredentialsSharesNothingQuietly(t *testing.T) {
	root, remote := gitCommandTeam(t)
	env := newShareEnv(t) // signed out, and any request fails the test
	prevOpts := shareOpts
	shareOpts = shareOptions{logPath: env.logPath}
	t.Cleanup(func() { shareOpts = prevOpts })
	old := mustGit(t, root, "rev-parse", "HEAD")
	mustGit(t, root, "commit", "-q", "--allow-empty", "-m", "agent work")
	sha := mustGit(t, root, "rev-parse", "HEAD")
	mustGit(t, root, "notes", "--ref="+gitlink.NotesRef, "add", "-m", "beacon:claude_code/"+shareTestSession, sha)
	if _, err := runGit(t, "setup", "--cwd", root, "--share-sessions"); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	rootCmd.SetIn(strings.NewReader("refs/heads/main " + sha + " refs/heads/main " + old + "\n"))
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	start := time.Now()
	if _, err := runGitStderr(t, &stderr, "hook", "pre-push", "--cwd", root, "origin", remote); err != nil || stderr.Len() != 0 {
		t.Fatalf("pre-push: %v %q", err, stderr.String())
	}
	if time.Since(start) > gitShareBudget {
		t.Fatal("pre-push exceeded its budget")
	}
	if note := mustGit(t, remote, "notes", "--ref="+gitlink.NotesRef, "show", sha); note != "beacon:claude_code/"+shareTestSession {
		t.Fatalf("remote note %q", note)
	}
}

func TestGitSetupShareSessionsRules(t *testing.T) {
	root, _ := gitCommandTeam(t)
	if _, err := runGit(t, "setup", "--cwd", root, "--share-sessions", "--share-notes=false"); err == nil {
		t.Fatal("--share-sessions with --share-notes=false accepted")
	}
	prev := shareIsTTY
	shareIsTTY = func() bool { return false }
	t.Cleanup(func() { shareIsTTY = prev })
	if _, err := runGit(t, "setup", "--cwd", root, "--share-sessions", "--share-visibility", "public"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("public without --yes: %v", err)
	}
	if out, err := runGit(t, "setup", "--cwd", root, "--share-sessions", "--share-visibility", "public", "--yes"); err != nil || !strings.Contains(out, "beacon.shareVisibility = public") {
		t.Fatalf("public --yes: %v\n%s", err, out)
	}
	if out, err := runGit(t, "setup", "--cwd", root, "--share-notes=false"); err != nil || !strings.Contains(out, "unset     beacon.shareSessions") {
		t.Fatalf("share-notes off: %v\n%s", err, out)
	}
	if out, _ := runGit(t, "status", "--cwd", root); !strings.Contains(out, "sessions    off") {
		t.Fatalf("status:\n%s", out)
	}
}

// Called straight from a hook manager (gitlink.HookCall), without Beacon's block to copy and
// replay stdin, the pre-push hook must leave stdin to the steps after it (`git lfs pre-push`),
// and still finds the pushed commits from HEAD and the remote's tracking branches.
func TestGitPrePushWithoutTheBlockLeavesStdinAlone(t *testing.T) {
	root, remote := gitCommandTeam(t)
	env := newShareEnv(t)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)
	prevOpts := shareOpts
	shareOpts = shareOptions{logPath: env.logPath}
	t.Cleanup(func() { shareOpts = prevOpts })
	t.Setenv(gitlink.HookStdinEnv, "")

	old := mustGit(t, root, "rev-parse", "HEAD")
	mustGit(t, root, "commit", "-q", "--allow-empty", "-m", "agent work")
	sha := mustGit(t, root, "rev-parse", "HEAD")
	mustGit(t, root, "notes", "--ref="+gitlink.NotesRef, "add", "-m", "beacon:claude_code/"+shareTestSession, sha)
	if _, err := runGit(t, "setup", "--cwd", root, "--share-sessions"); err != nil {
		t.Fatal(err)
	}
	stdin := "refs/heads/main " + sha + " refs/heads/main " + old + "\n"
	reader := strings.NewReader(stdin)
	rootCmd.SetIn(reader)
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	var stderr bytes.Buffer
	if _, err := runGitStderr(t, &stderr, "hook", "pre-push", "--cwd", root, "origin", remote); err != nil || stderr.Len() != 0 {
		t.Fatalf("pre-push: %v %q", err, stderr.String())
	}
	if reader.Len() != len(stdin) {
		t.Fatalf("the hook read %d bytes of stdin that the next step needs", len(stdin)-reader.Len())
	}
	want := "beacon:claude_code/" + shareTestSession + " https://beacon.sh/s/k3xabc"
	if note := mustGit(t, remote, "notes", "--ref="+gitlink.NotesRef, "show", sha); note != want {
		t.Fatalf("remote note %q, want the session shared from HEAD", note)
	}
}

// Pre-push sharing to a trace that already exists keeps the title set on it earlier (with --title
// or a rename on beacon.sh) and its visibility.
func TestGitPrePushKeepsAnExistingTracesTitle(t *testing.T) {
	root, remote := gitCommandTeam(t)
	env := newShareEnv(t)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)
	// Shared from elsewhere (another log, so this machine's log has no record of it), titled.
	elsewhere := filepath.Join(t.TempDir(), "other.jsonl")
	if _, stderr, err := runShareCommand(t, "--cwd", env.projectDir, "--title", "Login fix", "--visibility", "private", "--log-path", elsewhere); err != nil {
		t.Fatalf("share: %v\n%s", err, stderr)
	}
	prevOpts := shareOpts
	shareOpts = shareOptions{logPath: env.logPath}
	t.Cleanup(func() { shareOpts = prevOpts })
	t.Setenv(gitlink.HookStdinEnv, "1")

	old := mustGit(t, root, "rev-parse", "HEAD")
	mustGit(t, root, "commit", "-q", "--allow-empty", "-m", "agent work")
	sha := mustGit(t, root, "rev-parse", "HEAD")
	mustGit(t, root, "notes", "--ref="+gitlink.NotesRef, "add", "-m", "beacon:claude_code/"+shareTestSession, sha)
	if _, err := runGit(t, "setup", "--cwd", root, "--share-sessions"); err != nil {
		t.Fatal(err)
	}
	rootCmd.SetIn(strings.NewReader("refs/heads/main " + sha + " refs/heads/main " + old + "\n"))
	t.Cleanup(func() { rootCmd.SetIn(nil) })
	var stderr bytes.Buffer
	before := len(srv.requests)
	if _, err := runGitStderr(t, &stderr, "hook", "pre-push", "--cwd", root, "origin", remote); err != nil || stderr.Len() != 0 {
		t.Fatalf("pre-push: %v %q", err, stderr.String())
	}
	if len(srv.requests) == before {
		t.Fatal("pre-push made no share request")
	}
	if srv.trace.Title != "Login fix" || srv.trace.Visibility != "private" {
		t.Fatalf("trace title %q visibility %q, want the ones set earlier", srv.trace.Title, srv.trace.Visibility)
	}
}
