package codexsession

import (
	"strings"
	"testing"
)

func TestDesktopClassificationSurvivesIncrementalSync(t *testing.T) {
	for _, tc := range []struct{ origin, want string }{
		{"Codex Desktop", "codex_desktop"},
		{"codex-app-server", "codex_desktop"},
		{"codex-tui", "codex_cli"},
		{"", "codex_cli"},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			meta := strings.Replace(sessionMetaLine("s", "/tmp"), "codex-tui", tc.origin, 1)
			meta = strings.Replace(meta, `"source":"cli"`, `"source":"vscode"`, 1)
			records := decodeFixture(t, []string{meta, messageLine("user", "u", "hello")})
			for _, min := range []int{0, 1} {
				mapped := MapSession(SessionRef{ID: "s"}, records, MapOptions{MinLine: min})
				if len(mapped) == 0 {
					t.Fatal("no events")
				}
				for _, e := range mapped {
					if e.Event.Harness.Name != tc.want {
						t.Fatalf("got %s, want %s", e.Event.Harness.Name, tc.want)
					}
				}
			}
		})
	}
}

func TestPerCompletionUsageDoesNotSumTurnTotals(t *testing.T) {
	for _, withUsage := range []bool{true, false} {
		records := []Record{
			{Line: 1, Entry: Entry{TokenUsageRecord: &TokenUsageRecord{TurnID: "t", TurnTokenUsage: &TokenUsage{InputTokens: 100, OutputTokens: 10}}}},
			{Line: 2, Entry: Entry{TokenUsageRecord: &TokenUsageRecord{TurnID: "t", TurnTokenUsage: &TokenUsage{InputTokens: 250, OutputTokens: 30}}}},
		}
		if withUsage {
			records[0].Entry.TokenUsageRecord.Usage = &TokenUsage{InputTokens: 100, OutputTokens: 10}
			records[1].Entry.TokenUsageRecord.Usage = &TokenUsage{InputTokens: 150, OutputTokens: 20}
		}
		for _, min := range []int{0, 1} {
			mapped := MapSession(SessionRef{ID: "s"}, records, MapOptions{MinLine: min})
			var input, output int64
			for _, e := range mapped {
				input += *e.Event.GenAI.Usage.InputTokens
				output += *e.Event.GenAI.Usage.OutputTokens
			}
			wantInput, wantOutput := int64(250), int64(30)
			if min == 1 {
				wantInput, wantOutput = 150, 20
			}
			if input != wantInput || output != wantOutput {
				t.Fatalf("withUsage=%v min=%d got %d/%d, want %d/%d", withUsage, min, input, output, wantInput, wantOutput)
			}
		}
	}
}

func TestExecOriginatorOverrideDoesNotBecomeDesktop(t *testing.T) {
	meta := strings.Replace(sessionMetaLine("s", "/tmp"), "codex-tui", "Codex Desktop", 1)
	meta = strings.Replace(meta, `"source":"cli"`, `"source":"exec"`, 1)
	mapped := MapSession(SessionRef{ID: "s"}, decodeFixture(t, []string{meta}), MapOptions{})
	if mapped[0].Event.Harness.Name != "codex_cli" {
		t.Fatal("exec incorrectly classified as Desktop")
	}
}
