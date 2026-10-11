package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/schema"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/handoff"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// growingSource is a Claude Code store whose one session gains events while --follow runs.
type growingSource struct {
	mu      sync.Mutex
	session handoff.Session
	events  []schema.Event
}

func (g *growingSource) Harness() string { return handoff.HarnessClaude }
func (g *growingSource) List() ([]handoff.Session, error) {
	return []handoff.Session{g.session}, nil
}
func (g *growingSource) Events(handoff.Session) ([]schema.Event, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]schema.Event(nil), g.events...), nil
}
func (g *growingSource) add(e schema.Event) {
	g.mu.Lock()
	g.events = append(g.events, e)
	g.mu.Unlock()
}

func followEvent(dir, ts, action string) schema.Event {
	e := schema.NewEvent(schema.NewEventOptions{Action: action, Category: "agent", Harness: schema.HarnessInfo{Name: handoff.HarnessClaude, CollectionMethod: schema.CollectionMethodPoll}})
	e.Timestamp = ts
	e.Session = &schema.SessionInfo{ID: shareTestSession, WorkingDirectory: dir}
	return e
}

func TestShareFollowUploadsNewMessagesUntilTheSessionEnds(t *testing.T) {
	env := newShareEnv(t)
	src := &growingSource{
		session: handoff.Session{Harness: handoff.HarnessClaude, ID: shareTestSession, Directory: env.projectDir, UpdatedAt: time.Now()},
		events:  shareFixtureEvents(env.projectDir),
	}
	stubHandoffSources(t, src)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)

	// The fake clock: each wait is one poll. Polls 1 and 3 add to the session, poll 2 adds
	// nothing (no request may be made for it), and poll 4 records the session's end.
	polls := 0
	requestsAt := map[int]int{}
	prevWait := shareFollowWait
	shareFollowWait = func(ctx context.Context, d time.Duration) error {
		if d != 2*time.Second {
			t.Errorf("interval = %s", d)
		}
		polls++
		srv.mu.Lock()
		requestsAt[polls] = len(srv.requests)
		srv.mu.Unlock()
		switch polls {
		case 1:
			m := followEvent(env.projectDir, "2026-10-01T10:01:00.000000000Z", "agent.message")
			m.GenAI = &schema.GenAIInfo{Output: &schema.GenAIOutputInfo{Messages: asymptoteobserve.TextOutputMessages("Second answer.")}}
			src.add(m)
		case 3:
			p := followEvent(env.projectDir, "2026-10-01T10:02:00.000000000Z", "prompt.submitted")
			p.Event.Category = "prompt"
			p.Prompt = &schema.PromptInfo{Text: "One more thing"}
			src.add(p)
		case 4:
			src.add(followEvent(env.projectDir, "2026-10-01T10:03:00.000000000Z", "session.ended"))
		case 10:
			return errors.New("the loop did not stop at the session's end")
		}
		return nil
	}
	t.Cleanup(func() { shareFollowWait = prevWait })

	stdout, stderr, err := runShareCommand(t, "--follow", "--interval", "2s", "--json", "--cwd", env.projectDir, "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("follow: %v\n%s", err, stderr)
	}
	if polls != 4 {
		t.Fatalf("polls = %d, want 4", polls)
	}
	srv.mu.Lock()
	if requestsAt[3] != requestsAt[2] {
		t.Errorf("an unchanged poll made requests: %v", srv.requests[requestsAt[2]:requestsAt[3]])
	}
	messages := len(srv.messages)
	srv.mu.Unlock()
	// The fixture's four, the second answer, the new prompt, and the session's end.
	if messages != 7 {
		t.Fatalf("server has %d messages, want 7", messages)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	var final struct {
		OK   bool              `json:"ok"`
		Data shareFollowUpdate `json:"data"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &final); err != nil || !final.Data.Final || !final.Data.Ended || final.Data.SharedURL != "https://beacon.sh/s/k3xabc" {
		t.Fatalf("last line %q (%v)", lines[len(lines)-1], err)
	}
	if n := len(shareEventsIn(t, env.logPath)); n != 2 {
		t.Fatalf("session.shared events = %d, want one for the share and one at the end", n)
	}
}

func TestShareFollowStopsOnInterrupt(t *testing.T) {
	env := newShareEnv(t)
	srv := newFakeShareServer(t)
	srv.signIn(account.ScopeTracesWrite)
	prevWait, prevSignals := shareFollowWait, shareFollowSignals
	var cancel context.CancelFunc
	shareFollowSignals = func(ctx context.Context) (context.Context, context.CancelFunc) {
		ctx, cancel = context.WithCancel(ctx)
		return ctx, cancel
	}
	shareFollowWait = func(ctx context.Context, d time.Duration) error {
		cancel() // Ctrl+C during the first wait
		return ctx.Err()
	}
	t.Cleanup(func() { shareFollowWait, shareFollowSignals = prevWait, prevSignals })
	stdout, stderr, err := runShareCommand(t, "--follow", "--cwd", env.projectDir, "--log-path", env.logPath)
	if err != nil {
		t.Fatalf("follow: %v", err)
	}
	if !strings.HasPrefix(stdout, "https://beacon.sh/s/k3xabc") || !strings.Contains(stderr, "Stopped following") {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}
	if _, _, err := runShareCommand(t, "--follow", "--print"); err == nil {
		t.Fatal("--follow --print accepted")
	}
}

func shareEventsIn(t *testing.T, logPath string) []schema.Event {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []schema.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var e schema.Event
		if json.Unmarshal([]byte(line), &e) == nil && e.Event.Action == SessionSharedAction {
			out = append(out, e)
		}
	}
	return out
}
