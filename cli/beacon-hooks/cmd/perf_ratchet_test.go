package cmd

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"testing"
)

// initAllocCeiling bounds the allocations this package's initialization makes, test files
// included (267 when it was set; 3,518 before the package-level patterns compiled on first use).
// Every hook run pays it before reading its input. Lower it when a change lowers the count.
const initAllocCeiling = 350

func TestHookInitStaysCheap(t *testing.T) {
	if os.Getenv("BEACON_INIT_TRACE_CHILD") != "" {
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHookInitStaysCheap$")
	cmd.Env = append(os.Environ(), "GODEBUG=inittrace=1", "BEACON_INIT_TRACE_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("re-run test binary: %v\n%s", err, out)
	}
	match := regexp.MustCompile(`(?m)^init github\.com/asymptote-labs/agent-beacon/cli/beacon-hooks/cmd @.* (\d+) allocs$`).FindSubmatch(out)
	if match == nil {
		t.Skipf("no init trace for this package in:\n%s", out)
	}
	allocs, _ := strconv.Atoi(string(match[1]))
	if allocs > initAllocCeiling {
		t.Fatalf("package init made %d allocations, ceiling %d; compile patterns on first use (sync.OnceValue)", allocs, initAllocCeiling)
	}
}
