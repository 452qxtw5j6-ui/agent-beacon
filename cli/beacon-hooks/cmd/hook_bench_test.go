package cmd

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// The hook benchmarks time one hook run in process, the work a runtime waits on before every tool
// call continues. Process start is not in them; `GODEBUG=inittrace=1 beacon-hooks version` shows
// package initialization, which every run also pays.

func benchmarkHook(b *testing.B, run func(*cobra.Command, []string), input map[string]interface{}) {
	setupHookConfigDirs(b)
	platformFlag = "claude"
	b.Setenv("BEACON_ENDPOINT_LOG", filepath.Join(b.TempDir(), "runtime.jsonl"))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		// A distinct call id per run, so no run is taken for a repeat of the one before.
		input["tool_use_id"] = fmt.Sprintf("toolu_%d", i)
		stdin, err := json.Marshal(input)
		if err != nil {
			b.Fatal(err)
		}
		runHookWithRawInput(b, run, stdin)
	}
}

func benchClaudePayload(event, tool string, toolInput map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"session_id":      "bench-session",
		"cwd":             "/repo",
		"hook_event_name": event,
		"tool_name":       tool,
		"tool_input":      toolInput,
		"tool_use_id":     "toolu_bench",
	}
}

func BenchmarkHookPreToolBash(b *testing.B) {
	benchmarkHook(b, runPreTool, benchClaudePayload("PreToolUse", "Bash", map[string]interface{}{"command": "go test ./... -count=1", "description": "Run tests"}))
}

func BenchmarkHookPostToolBashOutput(b *testing.B) {
	var out strings.Builder
	for i := 0; i < 400; i++ {
		fmt.Fprintf(&out, "ok  \tgithub.com/example/project/internal/pkg%d\t0.%03ds  // refreshes the api token cache\n", i, i)
	}
	input := benchClaudePayload("PostToolUse", "Bash", map[string]interface{}{"command": "go test ./..."})
	input["tool_response"] = map[string]interface{}{"stdout": out.String(), "stderr": "", "interrupted": false}
	benchmarkHook(b, runPostTool, input)
}

func BenchmarkHookPostToolReadCode(b *testing.B) {
	var code strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&code, "func load%d(cfg Config) (string, error) { token := cfg.Token; if token == \"\" { return \"\", errMissing }; return token, nil }\n", i)
	}
	input := benchClaudePayload("PostToolUse", "Read", map[string]interface{}{"file_path": "/repo/config.go"})
	input["tool_response"] = map[string]interface{}{"type": "text", "file": map[string]interface{}{"filePath": "/repo/config.go", "content": code.String()}}
	benchmarkHook(b, runPostTool, input)
}

func BenchmarkHookPromptSubmit(b *testing.B) {
	input := benchClaudePayload("UserPromptSubmit", "", nil)
	input["prompt"] = strings.Repeat("Please refactor the token refresh logic in auth.go so the api key is read from the env, then run the tests. ", 8)
	benchmarkHook(b, runPromptSubmit, input)
}
