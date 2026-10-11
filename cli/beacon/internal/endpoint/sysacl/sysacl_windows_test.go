//go:build windows

package sysacl

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// requireElevated skips when this process cannot set Administrators as an owner. The endpoint
// install already requires elevation and the Windows CI runner has it; an unelevated contributor
// should see a skip, not a red suite.
func requireElevated(t *testing.T) {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Skipf("open the process token: %v", err)
	}
	defer token.Close()
	if !token.IsElevated() {
		t.Skip("setting the Beacon ACLs needs an elevated shell")
	}
}

func icacls(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func mustRead(t *testing.T, path string) Object {
	t.Helper()
	obj, err := ReadObject(path)
	if err != nil {
		t.Fatalf("read the security of %s: %v", path, err)
	}
	return obj
}

// assertNoUserMayChange checks the directory itself, as read back from Windows: owned by
// Administrators, inheritance off, and no principal other than SYSTEM and Administrators holds a
// right that adds, removes or renames entries, writes its attributes, or changes its security.
func assertNoUserMayChange(t *testing.T, dir string) {
	t.Helper()
	obj := mustRead(t, dir)
	if obj.Owner != sidAdministrators {
		t.Errorf("%s is owned by %s, want Administrators", dir, obj.Owner)
	}
	if !obj.Protected {
		t.Errorf("%s still inherits from its parent", dir)
	}
	for _, ace := range obj.DACL {
		if ace.Type != aceTypeAllowed || trustedPrincipal(ace.SID) || ace.Flags&aceInheritOnly != 0 {
			continue
		}
		if bad := ace.Mask & (fileWriteData | fileAppendData | fileDeleteChild | accessDelete | writeDAC | writeOwner | fileWriteAttributes | genericWrite | genericAll); bad != 0 {
			t.Errorf("%s grants %s 0x%x on the directory itself", dir, ace.SID, bad)
		}
	}
}

func TestSecureLogDirReplacesTheLegacyGrant(t *testing.T) {
	requireElevated(t)
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"runtime.jsonl", "runtime.jsonl.lock", "runtime.jsonl.1", "operator-notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	icacls(t, dir, "/grant", `*S-1-5-4:(OI)(CI)(M)`, "/T")
	notesBefore := mustRead(t, filepath.Join(dir, "operator-notes.txt"))

	if err := SecureLogDir(dir, "runtime.jsonl"); err != nil {
		t.Fatalf("SecureLogDir: %v", err)
	}

	assertNoUserMayChange(t, dir)
	state, err := InspectLogDir(dir, "runtime.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Problems) > 0 {
		t.Fatalf("the secured log directory reads back with problems: %v", state.Problems)
	}
	if !state.HooksCanAppend {
		t.Fatal("hooks can no longer append to the secured log")
	}
	for _, name := range []string{"runtime.jsonl", "runtime.jsonl.lock", "runtime.jsonl.1"} {
		obj := mustRead(t, filepath.Join(dir, name))
		want := InheritedDACL(LogDirDACL(), false)
		if !reflect.DeepEqual(obj.DACL, want) {
			t.Errorf("%s carries %+v, want exactly the inherited %+v", name, obj.DACL, want)
		}
	}
	// A file outside the log family is the operator's, and Beacon never writes it.
	if notesAfter := mustRead(t, filepath.Join(dir, "operator-notes.txt")); !reflect.DeepEqual(notesBefore, notesAfter) {
		t.Errorf("a file outside the log family was changed: %+v -> %+v", notesBefore, notesAfter)
	}

	// New files -- the log the collector re-creates on rotation -- inherit the append grant and
	// nothing more.
	rotated := filepath.Join(dir, "runtime.jsonl.2")
	if err := os.WriteFile(rotated, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	obj := mustRead(t, rotated)
	if !CanAppend(obj.DACL, obj.NullDACL, false) {
		t.Errorf("a newly created log does not inherit the append grant: %+v", obj.DACL)
	}
	if problems := Problems(Object{Owner: sidAdministrators, DACL: obj.DACL}, KindLogFile); len(problems) > 0 {
		t.Errorf("a newly created log inherits too much: %v", problems)
	}
}

// A junction in place of the log directory sends every SYSTEM write to its target. Securing the
// path must replace the link with a real directory and leave the target untouched.
func TestSecureLogDirReplacesAJunctionWithoutTouchingItsTarget(t *testing.T) {
	requireElevated(t)
	root := t.TempDir()
	target := filepath.Join(root, "elsewhere")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "logs")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, target).CombinedOutput(); err != nil {
		t.Skipf("create a junction: %v: %s", err, strings.TrimSpace(string(out)))
	}
	before := mustRead(t, target)

	if err := SecureLogDir(dir, "runtime.jsonl"); err != nil {
		t.Fatalf("SecureLogDir: %v", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 || !info.IsDir() {
		t.Fatalf("%s is still a link (mode %v)", dir, info.Mode())
	}
	assertNoUserMayChange(t, dir)
	if after := mustRead(t, target); !reflect.DeepEqual(before, after) {
		t.Fatalf("the junction's target was re-secured: %+v -> %+v", before, after)
	}
}

// Links planted under the old grant -- a symbolic link named like the lock, a hard link named like
// an archive -- are removed, never followed, and what they point to keeps its security.
func TestSecureLogDirRemovesPlantedLinks(t *testing.T) {
	requireElevated(t)
	root := t.TempDir()
	victim := filepath.Join(root, "victim.txt")
	if err := os.WriteFile(victim, []byte("not Beacon's"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	before := mustRead(t, victim)

	planted := []string{}
	if err := os.Symlink(victim, filepath.Join(dir, "runtime.jsonl.lock")); err == nil {
		planted = append(planted, "runtime.jsonl.lock")
	}
	if err := os.Link(victim, filepath.Join(dir, "runtime.jsonl.3")); err == nil {
		planted = append(planted, "runtime.jsonl.3")
	}
	if len(planted) == 0 {
		t.Skip("could not create either kind of link here")
	}

	if err := SecureLogDir(dir, "runtime.jsonl"); err != nil {
		t.Fatalf("SecureLogDir: %v", err)
	}
	for _, name := range planted {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("the planted link %s survived: %v", name, err)
		}
	}
	if data, err := os.ReadFile(victim); err != nil || string(data) != "not Beacon's" {
		t.Fatalf("the link target was changed or removed: %q, %v", data, err)
	}
	if after := mustRead(t, victim); !reflect.DeepEqual(before, after) {
		t.Fatalf("the link target was re-secured: %+v -> %+v", before, after)
	}
}

// %ProgramData% lets any user create a subdirectory, so %ProgramData%\Beacon may exist, owned by
// someone else, before the package is installed. It is reset, not trusted; what is unsafe below it
// is reset; what an administrator deliberately locked down further is left alone.
func TestSecureSystemTreeResetsAPreCreatedRoot(t *testing.T) {
	requireElevated(t)
	root := filepath.Join(t.TempDir(), "Beacon")
	open := filepath.Join(root, "Endpoint", "hooks")
	locked := filepath.Join(root, "Endpoint", "asymptote")
	logs := filepath.Join(root, "Endpoint", "logs")
	for _, d := range []string{open, logs} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(open, "beacon-hooks.exe")
	if err := os.WriteFile(binary, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Users full control over the whole tree, as a directory someone else made might grant.
	icacls(t, root, "/grant", `*S-1-5-32-545:(OI)(CI)(F)`, "/T")
	// Created afterwards and cut off from it: owned by Administrators, SYSTEM and Administrators
	// only. Stricter than the tree, and so to be left alone.
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	icacls(t, locked, "/inheritance:r", "/grant:r", `*S-1-5-18:(OI)(CI)(F)`, `*S-1-5-32-544:(OI)(CI)(F)`)
	icacls(t, locked, "/setowner", `*S-1-5-32-544`)
	lockedBefore := mustRead(t, locked)
	logsBefore := mustRead(t, logs)

	if err := SecureSystemTree(root, logs); err != nil {
		t.Fatalf("SecureSystemTree: %v", err)
	}

	assertNoUserMayChange(t, root)
	if obj := mustRead(t, root); !reflect.DeepEqual(obj.DACL, TreeDACL()) {
		t.Errorf("the root carries %+v, want %+v", obj.DACL, TreeDACL())
	}
	for _, p := range []string{filepath.Join(root, "Endpoint"), open} {
		if problems, err := InspectTree(p, KindDir); err != nil || len(problems) > 0 {
			t.Errorf("%s after the reset: %v, %v", p, problems, err)
		}
	}
	if problems, err := InspectTree(binary, KindFile); err != nil || len(problems) > 0 {
		t.Errorf("the hooks binary after the reset: %v, %v", problems, err)
	}
	if after := mustRead(t, locked); !reflect.DeepEqual(lockedBefore, after) {
		t.Errorf("a directory already locked down further was changed: %+v -> %+v", lockedBefore, after)
	}
	if after := mustRead(t, logs); !reflect.DeepEqual(logsBefore, after) {
		t.Errorf("the skipped log directory was changed: %+v -> %+v", logsBefore, after)
	}
}
