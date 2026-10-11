package cmd

import (
	"runtime"
	"strings"
	"testing"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/diagnostics"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/lifecycle"
)

// TestLogPermissionRemediationMatchesThePlatformThatFailed guards advice, which is the part of
// doctor nobody tests and everybody follows.
//
// The check used to end in an unconditional `chmod 666`. That was right while only POSIX reached
// it. Windows reaches it now, where chmod does not exist and would not restore an ACL if it did --
// so the most consequential line doctor prints there, the remediation for a system-mode log that
// hooks cannot write, was a command that cannot work. A wrong fix is worse than none: the operator
// runs it, nothing changes, and the next thing they doubt is the diagnosis.
func TestLogPermissionRemediationMatchesThePlatformThatFailed(t *testing.T) {
	action := func(evidence string) string {
		return actionForCheck(diagnostics.Check{
			Name:     "runtime_log_permissions",
			Target:   `C:\ProgramData\Beacon\Endpoint\logs`,
			Evidence: evidence,
		}, lifecycle.RuntimeLogSource{})
	}

	// Every ACL evidence is Windows-only by construction, so none of them may produce POSIX advice.
	for _, evidence := range []string{
		"acl_missing_interactive_write",
		"acl_too_broad",
		"acl_not_writable_by_user",
		"acl_unreadable",
	} {
		got := action(evidence)
		if got == "" {
			t.Fatalf("evidence %q produced no remediation at all", evidence)
		}
		if strings.Contains(got, "chmod") {
			t.Fatalf("evidence %q suggests %q; chmod does not exist on Windows and would not "+
				"restore an ACL if it did", evidence, got)
		}
	}

	// The system-mode ACL is the one that decides whether an endpoint captures anything -- and,
	// when it is too broad, whether a user can redirect a SYSTEM write -- so its advice has to be
	// the actual repair, not a gesture at the problem. Both evidences get the same one.
	for _, evidence := range []string{"acl_missing_interactive_write", "acl_too_broad"} {
		grant := action(evidence)
		if runtime.GOOS == "windows" {
			if !strings.Contains(grant, "doctor") || !strings.Contains(grant, "--fix") || !strings.Contains(grant, "--system") {
				t.Fatalf("the %s remediation is %q; it should be the elevated doctor --system --fix "+
					"repair, which applies the same ACL install does", evidence, grant)
			}
		} else if grant != "beacon endpoint doctor --fix" {
			// No such ACL exists here, so the hint is empty and the advice falls back to the
			// command that does apply. Printing a Windows command on a Mac would be worse than
			// saying nothing.
			t.Fatalf("off Windows the %s remediation is %q, want the doctor --fix fallback", evidence, grant)
		}
	}

	if runtime.GOOS != "windows" {
		if got := action("not_writable"); got != `chmod 666 C:\ProgramData\Beacon\Endpoint\logs` {
			t.Fatalf("the POSIX mode remediation changed: %q", got)
		}
	}

	// A user-mode log is private; the mode remediation must never advise making it world-writable.
	if runtime.GOOS != "windows" {
		userAction := actionForCheck(diagnostics.Check{
			Name:     "runtime_log_permissions",
			Target:   "/home/someone/.beacon/endpoint/logs/runtime.jsonl",
			Evidence: "not_writable",
		}, lifecycle.RuntimeLogSource{EffectiveUserMode: true})
		if userAction != "chmod 600 /home/someone/.beacon/endpoint/logs/runtime.jsonl" {
			t.Fatalf("the user-mode remediation is %q; want owner-only chmod 600", userAction)
		}
	}

	if got := action("runtime_log_missing"); got != "beacon endpoint doctor --fix" {
		t.Fatalf("missing-log remediation = %q", got)
	}
}
