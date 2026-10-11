package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/dashboard"
)

func TestTopLevelTracesCommandIsRegistered(t *testing.T) {
	command, _, err := rootCmd.Find([]string{"traces"})
	if err != nil {
		t.Fatalf("find traces command: %v", err)
	}
	if command != topLevelTracesCmd {
		t.Fatalf("root traces command = %p, want %p", command, topLevelTracesCmd)
	}
}

func TestPrintPlainTraceList(t *testing.T) {
	result := dashboard.TraceListResultV1{
		Traces: []dashboard.TraceSummaryV1{{
			ID:        "session:cursor:s1",
			Title:     "A local trace",
			UpdatedAt: "2026-09-21T08:00:00Z",
			Harness:   dashboard.TraceHarnessV1{Name: "cursor"},
		}},
		TotalMatched: 150,
		Returned:     1,
		Truncated:    true,
	}
	var out bytes.Buffer
	printPlainTraceList(&out, result)
	for _, want := range []string{
		"session:cursor:s1\tcursor\t2026-09-21T08:00:00Z\tA local trace",
		"Showing 1 of 150 traces",
		"beacon endpoint traces list --page",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("plain output missing %q:\n%s", want, out.String())
		}
	}
}

func TestPlainTraceListShowsSharing(t *testing.T) {
	var out bytes.Buffer
	printPlainTraceList(&out, dashboard.TraceListResultV1{Traces: []dashboard.TraceSummaryV1{
		{ID: "session:claude_code:s7", Title: "a", Harness: dashboard.TraceHarnessV1{Name: "claude_code"}, Sharing: dashboard.TraceSharingV1{State: "stale", URL: "https://beacon.sh/s/x", RefreshCommand: "beacon share refresh claude_code:s7"}},
		{ID: "session:claude_code:s8", Title: "b", Harness: dashboard.TraceHarnessV1{Name: "claude_code"}, Sharing: dashboard.TraceSharingV1{State: "local_only"}},
	}})
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if !strings.HasSuffix(lines[0], "\tstale https://beacon.sh/s/x (beacon share refresh claude_code:s7)") || strings.Count(lines[1], "\t") != 3 {
		t.Fatalf("output:\n%s", out.String())
	}
}
