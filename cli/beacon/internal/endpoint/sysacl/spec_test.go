package sysacl

import (
	"strings"
	"testing"
)

const (
	someUser = "S-1-5-21-1111111111-2222222222-3333333333-1001"
	// icacls (M): everything in (RX) and (W) plus DELETE.
	modify = 0x001301BF
)

func TestThePolicyIsSafeByItsOwnRules(t *testing.T) {
	cases := []struct {
		name string
		obj  Object
		kind Kind
	}{
		{"tree root", Object{Owner: sidAdministrators, Protected: true, DACL: TreeDACL()}, KindDir},
		{"log directory", Object{Owner: sidAdministrators, Protected: true, DACL: LogDirDACL()}, KindLogDir},
		{"a directory in the tree", Object{Owner: sidAdministrators, DACL: InheritedDACL(TreeDACL(), true)}, KindDir},
		{"a file in the tree", Object{Owner: sidAdministrators, DACL: InheritedDACL(TreeDACL(), false)}, KindFile},
		{"the runtime log", Object{Owner: sidSystem, DACL: InheritedDACL(LogDirDACL(), false)}, KindLogFile},
		{"a subdirectory of the log directory", Object{Owner: sidAdministrators, DACL: InheritedDACL(LogDirDACL(), true)}, KindDir},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if problems := Problems(tc.obj, tc.kind); len(problems) > 0 {
				t.Fatalf("the ACL Beacon applies fails its own check: %v", problems)
			}
		})
	}
}

// The finding this package exists for: each of these let an ordinary user redirect a SYSTEM write.
func TestProblemsCatchesWhatLetAUserRedirectASystemWrite(t *testing.T) {
	cases := []struct {
		name string
		obj  Object
		kind Kind
	}{
		{
			// The grant every endpoint carried before: Modify for INTERACTIVE, (OI)(CI), on the
			// log directory. Adding, deleting and junctioning entries all follow from it.
			name: "the legacy Modify grant on the log directory",
			obj: Object{Owner: sidAdministrators, DACL: append(TreeDACL(),
				ACE{Type: aceTypeAllowed, Flags: aceObjectInherit | aceContainerInherit, Mask: modify, SID: sidInteractive})},
			kind: KindLogDir,
		},
		{
			// What the same grant left on the log itself after icacls /T.
			name: "Modify on the runtime log",
			obj: Object{Owner: sidAdministrators, DACL: append(InheritedDACL(TreeDACL(), false),
				ACE{Type: aceTypeAllowed, Mask: modify, SID: sidInteractive})},
			kind: KindLogFile,
		},
		{
			// %ProgramData% lets any user create a subdirectory, which they then own.
			name: "a directory a non-administrator created",
			obj:  Object{Owner: someUser, DACL: TreeDACL()},
			kind: KindDir,
		},
		{
			// What a directory MkdirAll creates under %ProgramData% inherits: Users may add files
			// and subdirectories.
			name: "the ACL inherited from %ProgramData%",
			obj: Object{Owner: sidAdministrators, DACL: []ACE{
				{Type: aceTypeAllowed, Flags: aceInherited | aceObjectInherit | aceContainerInherit, Mask: fileAllAccess, SID: sidSystem},
				{Type: aceTypeAllowed, Flags: aceInherited | aceObjectInherit | aceContainerInherit, Mask: fileAllAccess, SID: sidAdministrators},
				{Type: aceTypeAllowed, Flags: aceInherited | aceObjectInherit | aceContainerInherit, Mask: readExecute, SID: sidUsers},
				{Type: aceTypeAllowed, Flags: aceInherited | aceContainerInherit, Mask: fileWriteData | fileAppendData | fileWriteEA | fileWriteAttributes, SID: sidUsers},
				{Type: aceTypeAllowed, Flags: aceInherited | aceObjectInherit | aceContainerInherit | aceInheritOnly, Mask: fileAllAccess, SID: sidCreatorOwner},
			}},
			kind: KindDir,
		},
		{
			name: "write access to the hooks binary every user runs",
			obj: Object{Owner: sidAdministrators, DACL: append(InheritedDACL(TreeDACL(), false),
				ACE{Type: aceTypeAllowed, Mask: fileAppendData, SID: sidUsers})},
			kind: KindFile,
		},
		{
			name: "an inherit-only grant that hands new files DELETE",
			obj: Object{Owner: sidAdministrators, DACL: append(TreeDACL(),
				ACE{Type: aceTypeAllowed, Flags: aceObjectInherit | aceInheritOnly, Mask: logAppend | accessDelete, SID: sidInteractive})},
			kind: KindLogDir,
		},
		{
			name: "a grant to change the security of the log",
			obj: Object{Owner: sidAdministrators, DACL: append(InheritedDACL(LogDirDACL(), false),
				ACE{Type: aceTypeAllowed, Mask: writeDAC, SID: sidInteractive})},
			kind: KindLogFile,
		},
		{
			name: "a null DACL",
			obj:  Object{Owner: sidAdministrators, NullDACL: true},
			kind: KindDir,
		},
		{
			name: "an entry of a type this does not model",
			obj:  Object{Owner: sidAdministrators, DACL: append(TreeDACL(), ACE{Type: 9, Mask: fileWriteData})},
			kind: KindDir,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if problems := Problems(tc.obj, tc.kind); len(problems) == 0 {
				t.Fatal("reported safe")
			}
		})
	}
}

// The log directory's only extra entry reaches files directly in it, never the directory itself
// (users must not add, remove or rename entries) and never a subdirectory.
func TestTheAppendGrantReachesOnlyTheLogFiles(t *testing.T) {
	if CanAppend(LogDirDACL(), false, false) {
		t.Fatal("the log directory itself is writable by interactive users")
	}
	if !CanAppend(LogDirDACL(), false, true) {
		t.Fatal("files created in the log directory are not appendable by interactive users")
	}
	file := InheritedDACL(LogDirDACL(), false)
	if !CanAppend(file, false, false) {
		t.Fatal("the runtime log does not inherit the append grant")
	}
	for _, ace := range InheritedDACL(LogDirDACL(), true) {
		if ace.SID == sidInteractive {
			t.Fatalf("a subdirectory of the log directory inherits %+v", ace)
		}
	}
	for _, ace := range file {
		if trustedPrincipal(ace.SID) {
			continue
		}
		if ace.Mask&(accessDelete|writeDAC|writeOwner|genericAll) != 0 {
			t.Fatalf("the runtime log grants %s 0x%x, which includes delete or re-securing it", ace.SID, ace.Mask)
		}
		if ace.Flags != aceInherited {
			t.Fatalf("an entry on the runtime log carries flags 0x%x, want only INHERITED_ACE", ace.Flags)
		}
	}
}

// What Go's os.OpenFile asks for on Windows, from syscall.Open: O_APPEND|O_CREATE|O_WRONLY for the
// log, and O_CREATE|O_RDWR (GENERIC_READ|GENERIC_WRITE) for the lock. If the grant ever stops
// covering either, every hook write fails with access denied.
func TestTheAppendGrantCoversWhatHookOpensRequest(t *testing.T) {
	appendOpen := uint32(fileAppendData | fileWriteAttributes | fileWriteEA | readControl | synchronize)
	lockOpen := uint32(fileGenericRead | fileGenericWrite)
	if logAppend&appendOpen != appendOpen {
		t.Fatalf("the grant 0x%x misses 0x%x of what an append open requests", logAppend, appendOpen&^logAppend)
	}
	if logAppend&lockOpen != lockOpen {
		t.Fatalf("the grant 0x%x misses 0x%x of what the lock open requests", logAppend, lockOpen&^logAppend)
	}
}

func TestCanAppendHonorsADeny(t *testing.T) {
	dacl := append([]ACE{{Type: aceTypeDenied, Mask: fileAppendData, SID: sidInteractive}}, InheritedDACL(LogDirDACL(), false)...)
	if CanAppend(dacl, false, false) {
		t.Fatal("a deny of append on the log reads as appendable")
	}
	other := append([]ACE{{Type: aceTypeDenied, Mask: fileReadData, SID: sidInteractive}}, InheritedDACL(LogDirDACL(), false)...)
	if !CanAppend(other, false, false) {
		t.Fatal("a deny of unrelated rights reads as a deny of append")
	}
}

func TestInheritedDACLFollowsTheWindowsRules(t *testing.T) {
	parent := []ACE{
		{Type: aceTypeAllowed, Flags: aceObjectInherit | aceContainerInherit, Mask: 1, SID: "A"},
		{Type: aceTypeAllowed, Flags: aceContainerInherit, Mask: 2, SID: "B"},
		{Type: aceTypeAllowed, Flags: aceObjectInherit, Mask: 3, SID: "C"},
		{Type: aceTypeAllowed, Flags: aceObjectInherit | aceNoPropagate | aceInheritOnly, Mask: 4, SID: "D"},
		{Type: aceTypeAllowed, Flags: aceContainerInherit | aceNoPropagate, Mask: 5, SID: "E"},
		{Type: aceTypeAllowed, Flags: 0, Mask: 6, SID: "F"},
		{Type: aceTypeAllowed, Flags: aceInherited | aceObjectInherit | aceContainerInherit | aceInheritOnly, Mask: 7, SID: "G"},
	}
	render := func(dacl []ACE) string {
		var parts []string
		for _, a := range dacl {
			parts = append(parts, a.SID+":"+sddlFlags(a.Flags))
		}
		return strings.Join(parts, " ")
	}
	if got, want := render(InheritedDACL(parent, false)), "A:ID C:ID D:ID G:ID"; got != want {
		t.Fatalf("file inherits %q, want %q", got, want)
	}
	if got, want := render(InheritedDACL(parent, true)), "A:OICIID B:CIID C:OIIOID E:ID G:OICIID"; got != want {
		t.Fatalf("directory inherits %q, want %q", got, want)
	}
}

// The descriptors are what an administrator reads in an audit, so their exact form is pinned.
func TestSDDLIsTheDocumentedACL(t *testing.T) {
	if got, want := SDDL(sidAdministrators, true, TreeDACL()),
		"O:S-1-5-32-544D:PAI(A;OICI;0x1f01ff;;;S-1-5-18)(A;OICI;0x1f01ff;;;S-1-5-32-544)(A;OICI;0x1200a9;;;S-1-5-32-545)"; got != want {
		t.Fatalf("tree SDDL = %s\nwant          %s", got, want)
	}
	if got, want := SDDL(sidAdministrators, true, LogDirDACL()),
		"O:S-1-5-32-544D:PAI(A;OICI;0x1f01ff;;;S-1-5-18)(A;OICI;0x1f01ff;;;S-1-5-32-544)(A;OICI;0x1200a9;;;S-1-5-32-545)(A;OINPIO;0x12019f;;;S-1-5-4)"; got != want {
		t.Fatalf("log directory SDDL = %s\nwant                   %s", got, want)
	}
	if got, want := SDDL(sidAdministrators, false, InheritedDACL(LogDirDACL(), false)),
		"O:S-1-5-32-544D:AI(A;ID;0x1f01ff;;;S-1-5-18)(A;ID;0x1f01ff;;;S-1-5-32-544)(A;ID;0x1200a9;;;S-1-5-32-545)(A;ID;0x12019f;;;S-1-5-4)"; got != want {
		t.Fatalf("runtime log SDDL = %s\nwant               %s", got, want)
	}
}

func TestIsLogFamily(t *testing.T) {
	for _, name := range []string{"runtime.jsonl", "RUNTIME.JSONL", "runtime.jsonl.lock", "runtime.jsonl.1", "runtime.jsonl.12"} {
		if !IsLogFamily(name, "runtime.jsonl") {
			t.Errorf("%s is not recognized as the runtime log family", name)
		}
	}
	for _, name := range []string{"cloud-backfill.jsonl", "runtime.jsonl.", "runtime.jsonl.tmp", "runtime.jsonl.1.bak", "xruntime.jsonl"} {
		if IsLogFamily(name, "runtime.jsonl") {
			t.Errorf("%s is wrongly recognized as the runtime log family", name)
		}
	}
}
