package dashboard

import (
	"testing"
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
