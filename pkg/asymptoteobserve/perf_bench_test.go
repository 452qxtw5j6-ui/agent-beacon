package asymptoteobserve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Benchmarks for the work a hook does on every event. perf_ratchet_test.go holds the deterministic
// ceilings; these give the time.

var benchSink string

func BenchmarkRedactShortFields(b *testing.B) {
	fields := []string{"info", "claude_code", "abc-123", "2026-10-12T03:47:36.515970306Z", "tool.invoked", "/home/user/project", "Bash", "toolu_01"}
	for i := 0; i < b.N; i++ {
		for _, field := range fields {
			benchSink = RedactString(field)
		}
	}
}

func BenchmarkRedactCommand(b *testing.B) {
	command := "cd /home/user/project/cli && go test ./internal/endpoint/... -run TestX -count=1 2>&1 | tail -50"
	for i := 0; i < b.N; i++ {
		benchSink = RedactString(command)
	}
}

func BenchmarkRedactOutput8K(b *testing.B) {
	output := strings.Repeat("ok  \tgithub.com/example/project/internal/endpoint\t0.123s  // refreshes the api token cache\n", 100)[:8192]
	b.SetBytes(int64(len(output)))
	for i := 0; i < b.N; i++ {
		benchSink = RedactString(output)
	}
}

// BenchmarkRedactCodeWithAssignments is the slow path: source code whose labels are followed by a
// separator, so the label patterns run.
func BenchmarkRedactCodeWithAssignments(b *testing.B) {
	code := strings.Repeat("func load(cfg Config) string { token := cfg.Token; return token }\n", 130)[:8192]
	b.SetBytes(int64(len(code)))
	for i := 0; i < b.N; i++ {
		benchSink = RedactString(code)
	}
}

// benchmarkDedupe checks a candidate against a log whose tail is full, as a long-lived install's
// always is. sessions is how many sessions the tail's lines are spread across.
func benchmarkDedupe(b *testing.B, sessions int) {
	path := filepath.Join(b.TempDir(), "runtime.jsonl")
	line := `{"event":{"action":"tool.invoked","category":"tool","id":"bea06685-774f-5ac2-9c14-2bcb68e4a551"},"gen_ai":{"tool":{"call":{"id":"toolu_%d"}}},"harness":{"collection_method":"hook","name":"claude_code"},"message":"Tool invocation observed","repository":"/home/user/project","sequence":%d,"session":{"id":"session-%d","working_directory":"/home/user/project"},"severity":"info","timestamp":"2026-10-12T03:47:36.515970306Z","tool":{"command":"ls -la","name":"Bash"},"vendor":"beacon"%s}` + "\n"
	output := `,"content":{"text":"` + strings.Repeat(`ok  \tgithub.com/example/project/internal/pkg\t0.123s\n`, 30) + `"}`
	var log strings.Builder
	for i := 0; log.Len() < 2*endpointDedupeTailBytes; i++ {
		extra := ""
		if i%2 == 0 {
			extra = output
		}
		fmt.Fprintf(&log, line, i, i, i%sessions, extra)
	}
	if err := os.WriteFile(path, []byte(log.String()), 0o600); err != nil {
		b.Fatal(err)
	}
	candidate := []byte(strings.TrimSpace(fmt.Sprintf(line, -1, 1, 0, "")))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsDuplicateEndpointEvent(path, candidate, EndpointDuplicateWindow)
	}
}

func BenchmarkDedupeOneSession(b *testing.B)    { benchmarkDedupe(b, 1) }
func BenchmarkDedupeEightSessions(b *testing.B) { benchmarkDedupe(b, 8) }
