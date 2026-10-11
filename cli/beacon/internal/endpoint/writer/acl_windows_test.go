//go:build windows

package writer

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// requireSystemACLRights skips a test that applies the system log ACL when this process cannot.
//
// Setting Administrators as the owner needs an elevated token, which the endpoint install already
// requires and the Windows CI runner has. Skipped rather than failed elsewhere: a contributor
// running the suite unelevated should not see a red suite for a step their shell cannot perform.
func requireSystemACLRights(t *testing.T) {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Skipf("open the process token: %v", err)
	}
	defer token.Close()
	if !token.IsElevated() {
		t.Skip("applying the system log ACL needs an elevated shell")
	}
}

// TestEnsureSystemLogWritableAndDoctorAgree exercises the halves against each other on a real
// directory: what install applies must read back as healthy, and the grant this replaced must read
// back as the problem it is.
func TestEnsureSystemLogWritableAndDoctorAgree(t *testing.T) {
	requireSystemACLRights(t)
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "runtime.jsonl")

	// The grant every endpoint installed before this change carries: Modify for INTERACTIVE on
	// the directory, recursively, over a log and an archive a hook created.
	for _, name := range []string{"runtime.jsonl", "runtime.jsonl.1"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := exec.Command("icacls", dir, "/grant", `*S-1-5-4:(OI)(CI)(M)`, "/T").CombinedOutput(); err != nil {
		t.Fatalf("apply the legacy grant: %v: %s", err, strings.TrimSpace(string(out)))
	}
	before, err := CheckSystemLogACL(path)
	if err != nil {
		t.Fatalf("read the legacy ACL: %v", err)
	}
	if len(before.Problems) == 0 {
		t.Fatal("doctor reads Modify for INTERACTIVE on the log directory as healthy; that grant " +
			"lets any logged-on user delete the log and plant links a SYSTEM write follows")
	}

	if err := EnsureSystemLogWritable(path); err != nil {
		t.Fatalf("EnsureSystemLogWritable: %v", err)
	}
	after, err := CheckSystemLogACL(path)
	if err != nil {
		t.Fatalf("read the ACL after securing: %v", err)
	}
	if len(after.Problems) > 0 {
		t.Fatalf("the ACL install applies reads back with problems: %v", after.Problems)
	}
	if !after.HooksCanAppend {
		t.Fatal("the ACL install applies reads back as not appendable by interactive users; " +
			"doctor would report a healthy endpoint as broken")
	}
	for _, target := range []string{path, path + ".lock"} {
		if _, err := os.Stat(target); err != nil {
			t.Fatalf("%s was not created; users cannot create files in the log directory, so "+
				"install has to: %v", target, err)
		}
	}

	// A deny entry outranks the grant, and doctor must say so: hooks would fail despite the
	// allow entry still being present.
	if out, err := exec.Command("icacls", path, "/deny", `*S-1-5-4:(AD)`).CombinedOutput(); err != nil {
		t.Fatalf("add a deny entry: %v: %s", err, strings.TrimSpace(string(out)))
	}
	denied, err := CheckSystemLogACL(path)
	if err != nil {
		t.Fatalf("read the ACL after denying: %v", err)
	}
	if denied.HooksCanAppend {
		t.Fatal("an explicit deny of append on the log reads as appendable")
	}
}

// TestGrantCommandHintIsTheRepairCommand covers the half of the repair an operator runs by hand.
// The ACL is several entries, an owner and a reset of the log's files, so the advice is the command
// that runs the same code install does rather than a hand-written equivalent that could drift.
func TestGrantCommandHintIsTheRepairCommand(t *testing.T) {
	hint := GrantCommandHint(`C:\ProgramData\Beacon\Endpoint\logs`)
	if !strings.Contains(hint, "doctor") || !strings.Contains(hint, "--fix") || !strings.Contains(hint, "--system") {
		t.Fatalf("GrantCommandHint = %q, want the elevated doctor --system --fix repair", hint)
	}
	if strings.Contains(hint, "icacls") {
		t.Fatalf("GrantCommandHint = %q still prints an icacls grant", hint)
	}
}
