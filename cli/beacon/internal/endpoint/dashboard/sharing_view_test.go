package dashboard

import (
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
