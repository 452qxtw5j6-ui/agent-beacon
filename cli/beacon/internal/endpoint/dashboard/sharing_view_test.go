package dashboard

import (
	"strings"
	"testing"
	"time"
)

func TestTraceSharingStateAndRefreshCommand(t *testing.T) {
	path := newTestLog(t, parityFixture())
	withoutHistory(t)
	list, err := ReadTraceList(path, TraceQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]TraceSummaryV1{}
	for _, trace := range list.Traces {
		byID[trace.ID] = trace
	}
	stale := byID["session:claude_code:s7"].Sharing
	if stale.State != "stale" || stale.URL != "https://beacon.sh/s/s7trace" || stale.RefreshCommand != "beacon share refresh claude_code:s7" {
		t.Fatalf("s7 sharing = %+v", stale)
	}
	current := byID["session:claude_code:s8"].Sharing
	if current.State != "shared" || current.Visibility != "private" || current.RefreshCommand == "" {
		t.Fatalf("s8 sharing = %+v (a commit link must not make it stale)", current)
	}
	if local := byID["session:opencode:s5"].Sharing; local.State != "local_only" || local.RefreshCommand != "" {
		t.Fatalf("s5 sharing = %+v", local)
	}
	staleOnly, err := ReadTraceList(path, TraceQuery{State: "stale", Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, trace := range staleOnly.Traces {
		found = found || trace.ID == "session:claude_code:s7"
	}
	if !found {
		t.Fatalf("--state stale missed s7: %+v", staleOnly.Traces)
	}
}

func TestSessionsCarrySharingState(t *testing.T) {
	path := newTestLog(t, parityFixture())
	result, err := ReadSessions(path, EventQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*SessionSharing{}
	for _, s := range result.Sessions {
		got[s.ID] = s.Sharing
	}
	if s := got["s7"]; s == nil || s.State != "stale" || s.RefreshCommand != "beacon share refresh claude_code:s7" {
		t.Fatalf("s7 = %+v", s)
	}
	if s := got["s8"]; s == nil || s.State != "shared" || s.Visibility != "private" {
		t.Fatalf("s8 = %+v", s)
	}
	if got["s5"] != nil {
		t.Fatalf("s5 = %+v, want no sharing", got["s5"])
	}
	detail, ok, err := ReadSessionDetail(path, "s7")
	if err != nil || !ok || detail.Session.Sharing == nil || detail.Session.Sharing.State != "stale" {
		t.Fatalf("detail = %+v %v %v", detail.Session.Sharing, ok, err)
	}
}

func sharingLines(lines ...string) [][]byte {
	out := make([][]byte, len(lines))
	for i, l := range lines {
		out[i] = []byte(l)
	}
	return out
}

func sessionSharing(t *testing.T, path string, query EventQuery) map[string]*SessionSharing {
	t.Helper()
	query.Limit = 50
	result, err := ReadSessions(path, query)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*SessionSharing{}
	for _, s := range result.Sessions {
		got[s.ID] = s.Sharing
	}
	return got
}

// A session's sharing state comes from all of its events, not the ones the filters kept: a share
// record outside the time range or another model's events still marks it shared, and activity
// outside them still makes the share stale.
func TestSessionSharingIgnoresFilters(t *testing.T) {
	path := newTestLog(t, sharingLines(
		// sh1: shared at 10:01, nothing after.
		`{"timestamp":"2026-06-11T10:00:00Z","event":{"id":"a1","action":"prompt.submitted","category":"prompt"},"harness":{"name":"claude_code"},"model":"opus","session":{"id":"sh1"},"prompt":{"text":"one"}}`,
		`{"timestamp":"2026-06-11T10:01:00Z","event":{"id":"a2","action":"session.shared","category":"session","fidelity":"inferred"},"harness":{"name":"claude_code"},"session":{"id":"sh1"},"raw":{"shared_url":"https://beacon.sh/s/sh1","visibility":"direct","shared_at":"2026-06-11T10:01:00Z","last_refreshed_at":"2026-06-11T10:01:00Z"}}`,
		// sh2: shared at 10:01, then activity at 12:00 on another model.
		`{"timestamp":"2026-06-11T10:00:00Z","event":{"id":"b1","action":"prompt.submitted","category":"prompt"},"harness":{"name":"claude_code"},"model":"opus","session":{"id":"sh2"},"prompt":{"text":"two"}}`,
		`{"timestamp":"2026-06-11T10:01:00Z","event":{"id":"b2","action":"session.shared","category":"session","fidelity":"inferred"},"harness":{"name":"claude_code"},"session":{"id":"sh2"},"raw":{"shared_url":"https://beacon.sh/s/sh2","visibility":"direct","shared_at":"2026-06-11T10:01:00Z","last_refreshed_at":"2026-06-11T10:01:00Z"}}`,
		`{"timestamp":"2026-06-11T12:00:00Z","event":{"id":"b3","action":"command.executed","category":"command"},"harness":{"name":"claude_code"},"model":"sonnet","session":{"id":"sh2"}}`,
	))
	withoutHistory(t)
	for name, query := range map[string]EventQuery{
		"time range": {Since: mustTime(t, "2026-06-11T09:59:00Z"), Until: mustTime(t, "2026-06-11T10:00:30Z")},
		"model":      {Model: "opus"},
		"none":       {},
	} {
		got := sessionSharing(t, path, query)
		if s := got["sh1"]; s == nil || s.State != "shared" || s.URL != "https://beacon.sh/s/sh1" {
			t.Fatalf("%s: sh1 = %+v, want shared", name, s)
		}
		if s := got["sh2"]; s == nil || s.State != "stale" {
			t.Fatalf("%s: sh2 = %+v, want stale from activity the filter hides", name, s)
		}
	}
}

// A share record says what its upload covered (shared_through, when the session was read): an
// event logged between that read and the record was not uploaded, so the share is stale even
// though the record is newer. A session followed with refreshes after its last events is not.
func TestSharingStalenessUsesSharedThrough(t *testing.T) {
	path := newTestLog(t, sharingLines(
		// st1: read at 10:01, event at 10:01:30 during the upload, record at 10:02.
		`{"timestamp":"2026-06-11T10:00:00Z","event":{"id":"c1","action":"prompt.submitted","category":"prompt"},"harness":{"name":"claude_code"},"session":{"id":"st1"},"prompt":{"text":"one"}}`,
		`{"timestamp":"2026-06-11T10:01:30Z","event":{"id":"c2","action":"agent.message","category":"agent"},"harness":{"name":"claude_code"},"session":{"id":"st1"}}`,
		`{"timestamp":"2026-06-11T10:02:00Z","event":{"id":"c3","action":"session.shared","category":"session","fidelity":"inferred"},"harness":{"name":"claude_code"},"session":{"id":"st1"},"raw":{"shared_url":"https://beacon.sh/s/st1","visibility":"direct","shared_at":"2026-06-11T10:02:00Z","last_refreshed_at":"2026-06-11T10:02:00Z","shared_through":"2026-06-11T10:01:00Z"}}`,
		// st2: followed; each upload's refresh covers the events before it.
		`{"timestamp":"2026-06-11T11:00:00Z","event":{"id":"d1","action":"prompt.submitted","category":"prompt"},"harness":{"name":"claude_code"},"session":{"id":"st2"},"prompt":{"text":"two"}}`,
		`{"timestamp":"2026-06-11T11:00:05Z","event":{"id":"d2","action":"session.shared","category":"session","fidelity":"inferred"},"harness":{"name":"claude_code"},"session":{"id":"st2"},"raw":{"shared_url":"https://beacon.sh/s/st2","visibility":"direct","shared_at":"2026-06-11T11:00:05Z","last_refreshed_at":"2026-06-11T11:00:05Z","shared_through":"2026-06-11T11:00:04Z"}}`,
		`{"timestamp":"2026-06-11T11:00:20Z","event":{"id":"d3","action":"agent.message","category":"agent"},"harness":{"name":"claude_code"},"session":{"id":"st2"}}`,
		`{"timestamp":"2026-06-11T11:00:31Z","event":{"id":"d4","action":"session.shared","category":"session","fidelity":"inferred"},"harness":{"name":"claude_code"},"session":{"id":"st2"},"raw":{"shared_url":"https://beacon.sh/s/st2","visibility":"direct","last_refreshed_at":"2026-06-11T11:00:31Z","shared_through":"2026-06-11T11:00:30Z"}}`,
	))
	withoutHistory(t)
	got := sessionSharing(t, path, EventQuery{})
	if s := got["st1"]; s == nil || s.State != "stale" {
		t.Fatalf("st1 = %+v, want stale: an event came in during the upload", s)
	}
	if s := got["st2"]; s == nil || s.State != "shared" {
		t.Fatalf("st2 = %+v, want shared: the follow's refresh covered every event", s)
	}
	list, err := ReadTraceList(path, TraceQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]TraceSummaryV1{}
	for _, trace := range list.Traces {
		byID[trace.ID] = trace
	}
	if s := byID["session:claude_code:st1"].Sharing.State; s != "stale" {
		t.Fatalf("trace st1 sharing = %q, want stale", s)
	}
	if s := byID["session:claude_code:st2"].Sharing.State; s != "shared" {
		t.Fatalf("trace st2 sharing = %q, want shared", s)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A share made from inside the session is followed by the runtime's events for the `beacon share`
// command and the agent's reply about it; those do not make it stale. A later unrelated tool call
// does.
func TestShareFromInsideTheSessionIsNotStale(t *testing.T) {
	inside := []string{
		`{"timestamp":"2026-06-11T10:00:00Z","event":{"id":"e1","action":"prompt.submitted","category":"prompt"},"harness":{"name":"claude_code"},"session":{"id":"in1"},"prompt":{"id":"p1","text":"share this session"}}`,
		`{"timestamp":"2026-06-11T10:00:05Z","event":{"id":"e2","action":"tool.invoked","category":"tool"},"harness":{"name":"claude_code"},"session":{"id":"in1"},"prompt":{"id":"p1"},"tool":{"name":"Bash","command":"beacon share --current"},"gen_ai":{"tool":{"call":{"id":"call-share"}}}}`,
		`{"timestamp":"2026-06-11T10:00:09Z","event":{"id":"e3","action":"session.shared","category":"session","fidelity":"inferred"},"harness":{"name":"claude_code"},"session":{"id":"in1"},"raw":{"shared_url":"https://beacon.sh/s/in1","visibility":"direct","shared_at":"2026-06-11T10:00:09Z","last_refreshed_at":"2026-06-11T10:00:09Z","shared_through":"2026-06-11T10:00:06Z"}}`,
		`{"timestamp":"2026-06-11T10:00:10Z","event":{"id":"e4","action":"tool.completed","category":"tool"},"harness":{"name":"claude_code"},"session":{"id":"in1"},"prompt":{"id":"p1"},"tool":{"name":"Bash"},"gen_ai":{"tool":{"call":{"id":"call-share"}}}}`,
		`{"timestamp":"2026-06-11T10:00:11Z","event":{"id":"e5","action":"command.executed","category":"command"},"harness":{"name":"claude_code"},"session":{"id":"in1"},"prompt":{"id":"p1"},"command":{"command":"beacon share --current"}}`,
		`{"timestamp":"2026-06-11T10:00:15Z","event":{"id":"e6","action":"agent.message","category":"agent"},"harness":{"name":"claude_code"},"session":{"id":"in1"},"prompt":{"id":"p1"},"message":"Shared: https://beacon.sh/s/in1"}`,
	}
	check := func(t *testing.T, lines []string, want string) {
		t.Helper()
		path := newTestLog(t, sharingLines(lines...))
		withoutHistory(t)
		if s := sessionSharing(t, path, EventQuery{})["in1"]; s == nil || s.State != want {
			t.Fatalf("session sharing = %+v, want %s", s, want)
		}
		list, err := ReadTraceList(path, TraceQuery{Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		for _, trace := range list.Traces {
			if trace.ID == "session:claude_code:in1" && trace.Sharing.State != want {
				t.Fatalf("trace sharing = %+v, want %s", trace.Sharing, want)
			}
		}
	}
	t.Run("share and its reply", func(t *testing.T) { check(t, inside, "shared") })
	t.Run("without turn ids", func(t *testing.T) {
		var bare []string
		for _, line := range inside {
			bare = append(bare, strings.ReplaceAll(line, `"prompt":{"id":"p1"},`, ""))
		}
		check(t, bare, "shared")
	})
	t.Run("later tool call", func(t *testing.T) {
		check(t, append(append([]string{}, inside...),
			`{"timestamp":"2026-06-11T10:05:00Z","event":{"id":"e7","action":"tool.invoked","category":"tool"},"harness":{"name":"claude_code"},"session":{"id":"in1"},"prompt":{"id":"p1"},"tool":{"name":"Edit","path":"main.go"},"gen_ai":{"tool":{"call":{"id":"call-edit"}}}}`,
		), "stale")
	})
	t.Run("reply after later work", func(t *testing.T) {
		check(t, append(append([]string{}, inside...),
			`{"timestamp":"2026-06-11T10:05:00Z","event":{"id":"e8","action":"prompt.submitted","category":"prompt"},"harness":{"name":"claude_code"},"session":{"id":"in1"},"prompt":{"id":"p2","text":"now fix the bug"}}`,
		), "stale")
	})
}

// A share made from outside the session (another terminal, --follow) does not hide the agent's
// later output: it was not uploaded, so the share is stale.
func TestShareFromOutsideTheSessionGoesStaleOnAReply(t *testing.T) {
	path := newTestLog(t, sharingLines(
		`{"timestamp":"2026-06-11T10:00:00Z","event":{"id":"o1","action":"prompt.submitted","category":"prompt"},"harness":{"name":"claude_code"},"session":{"id":"out1"},"prompt":{"text":"work"}}`,
		`{"timestamp":"2026-06-11T10:00:09Z","event":{"id":"o2","action":"session.shared","category":"session","fidelity":"inferred"},"harness":{"name":"claude_code"},"session":{"id":"out1"},"raw":{"shared_url":"https://beacon.sh/s/out1","visibility":"direct","shared_at":"2026-06-11T10:00:09Z","last_refreshed_at":"2026-06-11T10:00:09Z","shared_through":"2026-06-11T10:00:06Z"}}`,
		`{"timestamp":"2026-06-11T10:00:15Z","event":{"id":"o3","action":"agent.message","category":"agent"},"harness":{"name":"claude_code"},"session":{"id":"out1"},"message":"Here is the answer."}`,
	))
	withoutHistory(t)
	if s := sessionSharing(t, path, EventQuery{})["out1"]; s == nil || s.State != "stale" {
		t.Fatalf("session sharing = %+v, want stale", s)
	}
	list, err := ReadTraceList(path, TraceQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	for _, trace := range list.Traces {
		if trace.ID == "session:claude_code:out1" && trace.Sharing.State != "stale" {
			t.Fatalf("trace sharing = %+v, want stale", trace.Sharing)
		}
	}
}
