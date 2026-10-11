// Package sysacl owns the Windows access control on the machine-wide Beacon directories:
// %ProgramData%\Beacon (config, collector config, the hooks binary every user's agent runs) and
// the system log directory beneath it.
//
// The model and the policy live in this file, which builds on every platform, so the decisions --
// which entries each directory carries, what a child inherits, what counts as a grant an ordinary
// user must not hold -- are tested on every CI leg rather than only on the Windows runner. The
// Windows file applies and reads them; elsewhere every entry point is a no-op, because POSIX
// carries the same guarantees in file modes and root ownership.
//
// # Why these ACLs
//
// The collector runs as LocalSystem and writes the runtime log; hooks run as whoever is at the
// keyboard and append to the same file. The original grant gave INTERACTIVE Modify on the log
// directory, recursively. Modify on a directory includes adding and deleting entries, so a user
// could empty it, turn it into a mount-point junction, and plant object-manager symbolic links
// named runtime.jsonl, runtime.jsonl.N or runtime.jsonl.lock -- and the next SYSTEM open, create or
// rename would land on a path of the user's choosing. Separately, nothing set the ACL on
// %ProgramData%\Beacon itself, which a non-administrator can create (and so own) before the
// package is ever installed.
//
// The policy below closes both. Every Beacon directory is owned by Administrators and carries a
// protected DACL (inheritance from %ProgramData% disabled): SYSTEM and Administrators full
// control, Users read and execute. The log directory adds exactly one more entry: an inherit-only
// grant to INTERACTIVE, applied to files directly inside it, of read and write data -- no DELETE,
// no WRITE_DAC, no WRITE_OWNER, and nothing on the directory itself. Ordinary users therefore
// cannot add, remove or rename anything in the directory, cannot turn it into a junction, and
// cannot change the security of the files they append to.
package sysacl

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Access rights, ACE types and ACE flags from winnt.h. Declared here rather than taken from
// x/sys/windows so the policy and its tests build on every platform; the values are part of the
// Windows ABI and do not change.
const (
	fileReadData        = 0x00000001 // FILE_LIST_DIRECTORY on a directory
	fileWriteData       = 0x00000002 // FILE_ADD_FILE on a directory
	fileAppendData      = 0x00000004 // FILE_ADD_SUBDIRECTORY on a directory
	fileReadEA          = 0x00000008
	fileWriteEA         = 0x00000010
	fileExecute         = 0x00000020 // FILE_TRAVERSE on a directory
	fileDeleteChild     = 0x00000040
	fileReadAttributes  = 0x00000080
	fileWriteAttributes = 0x00000100

	accessDelete         = 0x00010000
	readControl          = 0x00020000
	writeDAC             = 0x00040000
	writeOwner           = 0x00080000
	synchronize          = 0x00100000
	accessSystemSecurity = 0x01000000
	maximumAllowed       = 0x02000000
	genericAll           = 0x10000000
	genericExecute       = 0x20000000
	genericWrite         = 0x40000000
	genericRead          = 0x80000000

	fileAllAccess      = 0x001F01FF
	fileGenericRead    = readControl | fileReadData | fileReadAttributes | fileReadEA | synchronize
	fileGenericWrite   = readControl | fileWriteData | fileWriteAttributes | fileWriteEA | fileAppendData | synchronize
	fileGenericExecute = readControl | fileReadAttributes | fileExecute | synchronize
)

const (
	aceTypeAllowed uint8 = 0
	aceTypeDenied  uint8 = 1
)

const (
	aceObjectInherit    uint8 = 0x01
	aceContainerInherit uint8 = 0x02
	aceNoPropagate      uint8 = 0x04
	aceInheritOnly      uint8 = 0x08
	aceInherited        uint8 = 0x10
)

// Well-known SIDs, by string form so the comparison never depends on the display language.
const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidUsers            = "S-1-5-32-545"
	sidInteractive      = "S-1-5-4"
	sidAuthenticated    = "S-1-5-11"
	sidEveryone         = "S-1-1-0"
	sidCreatorOwner     = "S-1-3-0"
	sidCreatorGroup     = "S-1-3-1"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// readExecute is what Users hold everywhere: list, traverse, read. Hooks read config.json and run
// hooks\beacon-hooks.exe from here, and duplicate detection reads the tail of the runtime log.
const readExecute = fileGenericRead | fileGenericExecute

// logAppend is the one write grant. Read plus FILE_GENERIC_WRITE, which is everything Go asks for
// when a hook opens the log for append (FILE_APPEND_DATA, FILE_WRITE_ATTRIBUTES, FILE_WRITE_EA,
// READ_CONTROL, SYNCHRONIZE) and when it opens runtime.jsonl.lock read-write to take the lock
// (adds FILE_WRITE_DATA). It deliberately excludes DELETE, WRITE_DAC and WRITE_OWNER.
//
// FILE_WRITE_DATA means a user can overwrite bytes already in the log, as the 0666 POSIX log
// allows. It is granted through inheritance rather than as an explicit entry on two files because
// the collector re-creates runtime.jsonl on every rotation (and the lock, if anyone removes it), and
// an entry inherited at creation is the only one that survives that without Beacon re-applying it.
const logAppend = fileGenericRead | fileGenericWrite

// ACE is one access control entry, in the shape both the policy and the reader use.
type ACE struct {
	Type  uint8
	Flags uint8
	Mask  uint32
	SID   string
}

// Object is the security of one file or directory, as read back.
type Object struct {
	Owner     string
	NullDACL  bool
	Protected bool
	DACL      []ACE
}

// TreeDACL is the protected DACL on %ProgramData%\Beacon, and what everything below it inherits.
func TreeDACL() []ACE {
	return []ACE{
		{Type: aceTypeAllowed, Flags: aceObjectInherit | aceContainerInherit, Mask: fileAllAccess, SID: sidSystem},
		{Type: aceTypeAllowed, Flags: aceObjectInherit | aceContainerInherit, Mask: fileAllAccess, SID: sidAdministrators},
		{Type: aceTypeAllowed, Flags: aceObjectInherit | aceContainerInherit, Mask: readExecute, SID: sidUsers},
	}
}

// LogDirDACL is the protected DACL on the system log directory: the tree's entries plus the
// inherit-only append grant, which applies to files directly in the directory (object inherit,
// inherit only, no propagate) and so never to the directory itself or to a subdirectory.
func LogDirDACL() []ACE {
	return append(TreeDACL(), ACE{
		Type:  aceTypeAllowed,
		Flags: aceObjectInherit | aceInheritOnly | aceNoPropagate,
		Mask:  logAppend,
		SID:   sidInteractive,
	})
}

// InheritedDACL is what a new child of a directory carrying parent receives, following the
// Windows inheritance rules for ACE flags. It is applied to existing children Beacon resets, so a
// reset child carries exactly what one created now would.
func InheritedDACL(parent []ACE, childIsDir bool) []ACE {
	var out []ACE
	for _, ace := range parent {
		flags := ace.Flags &^ aceInherited
		oi := flags&aceObjectInherit != 0
		ci := flags&aceContainerInherit != 0
		np := flags&aceNoPropagate != 0
		if !childIsDir {
			if oi {
				out = append(out, ACE{Type: ace.Type, Flags: aceInherited, Mask: ace.Mask, SID: ace.SID})
			}
			continue
		}
		switch {
		case ci && np:
			out = append(out, ACE{Type: ace.Type, Flags: aceInherited, Mask: ace.Mask, SID: ace.SID})
		case ci:
			out = append(out, ACE{Type: ace.Type, Flags: aceInherited | (flags & (aceObjectInherit | aceContainerInherit)), Mask: ace.Mask, SID: ace.SID})
		case oi && !np:
			// Carried through the directory, inherit-only, for the files inside it.
			out = append(out, ACE{Type: ace.Type, Flags: aceInherited | aceObjectInherit | aceInheritOnly, Mask: ace.Mask, SID: ace.SID})
		}
	}
	return out
}

// SDDL renders an owner and DACL as a security descriptor string. Protected descriptors are the
// roots Beacon owns outright; unprotected ones are children carrying inherited entries.
func SDDL(owner string, protected bool, dacl []ACE) string {
	var b strings.Builder
	b.WriteString("O:" + owner + "D:")
	if protected {
		b.WriteString("P")
	}
	b.WriteString("AI")
	for _, ace := range dacl {
		kind := "A"
		if ace.Type == aceTypeDenied {
			kind = "D"
		}
		fmt.Fprintf(&b, "(%s;%s;0x%x;;;%s)", kind, sddlFlags(ace.Flags), ace.Mask, ace.SID)
	}
	return b.String()
}

func sddlFlags(flags uint8) string {
	var s string
	for _, f := range []struct {
		bit  uint8
		name string
	}{{aceObjectInherit, "OI"}, {aceContainerInherit, "CI"}, {aceNoPropagate, "NP"}, {aceInheritOnly, "IO"}, {aceInherited, "ID"}} {
		if flags&f.bit != 0 {
			s += f.name
		}
	}
	return s
}

// trustedPrincipal reports whether a SID may hold write, delete or ownership rights anywhere in
// Beacon's machine-wide directories.
func trustedPrincipal(sid string) bool {
	switch sid {
	case sidSystem, sidAdministrators, sidTrustedInstaller:
		return true
	}
	return false
}

// coversInteractiveUsers reports whether a grant to this SID reaches a hook running as the person
// at the keyboard.
func coversInteractiveUsers(sid string) bool {
	switch sid {
	case sidInteractive, sidUsers, sidAuthenticated, sidEveryone:
		return true
	}
	return false
}

// Rights an untrusted principal must never hold on a Beacon directory: adding or removing
// entries, deleting it, writing the attributes or reparse data that turn it into a junction, or
// changing its security.
const dirForbidden = fileWriteData | fileAppendData | fileWriteEA | fileWriteAttributes | fileDeleteChild |
	accessDelete | writeDAC | writeOwner | accessSystemSecurity | maximumAllowed | genericAll | genericWrite

// Rights an untrusted principal must never hold on a Beacon file other than the runtime log
// family: config, the collector config and the hooks binary are read by SYSTEM or run by every
// user, so any write is a privilege escalation.
const fileForbidden = fileWriteData | fileAppendData | fileWriteEA | fileWriteAttributes |
	accessDelete | writeDAC | writeOwner | accessSystemSecurity | maximumAllowed | genericAll | genericWrite

// Rights an untrusted principal must never hold on the runtime log, its archives or its lock.
// Appending is the point; deleting, renaming or re-securing them is the attack.
const logFileForbidden = accessDelete | writeDAC | writeOwner | accessSystemSecurity | maximumAllowed | genericAll

// Kind says which rules an object is held to.
type Kind int

const (
	KindDir     Kind = iota // a directory in the Beacon tree
	KindFile                // a file in the Beacon tree
	KindLogDir              // the system log directory
	KindLogFile             // runtime.jsonl, its archives, or its lock
)

// Problems lists every reason obj is not safe to leave as it is. Empty means safe.
//
// An entry counts by what it grants, wherever it applies: to the object itself (unless it is
// inherit-only), and, on a directory, to the files (object inherit) and subdirectories (container
// inherit) created in it later. Deny entries never make an object less safe and are ignored.
// Entries of a type this does not model are treated as grants, so an unfamiliar ACL is reset
// rather than trusted.
func Problems(obj Object, kind Kind) []string {
	var out []string
	if !trustedPrincipal(obj.Owner) {
		out = append(out, "owned by "+obj.Owner+", not SYSTEM or Administrators")
	}
	if obj.NullDACL {
		return append(out, "has no DACL, which grants everyone full control")
	}
	isDir := kind == KindDir || kind == KindLogDir
	selfForbidden := uint32(fileForbidden)
	switch kind {
	case KindDir, KindLogDir:
		selfForbidden = dirForbidden
	case KindLogFile:
		selfForbidden = logFileForbidden
	}
	for _, ace := range obj.DACL {
		if ace.Type == aceTypeDenied || trustedPrincipal(ace.SID) {
			continue
		}
		if ace.SID == sidCreatorOwner || ace.SID == sidCreatorGroup {
			// Stand-ins resolved to whoever creates the child. Only trusted principals can
			// create anything here once the directory itself is safe.
			continue
		}
		if ace.Flags&aceInheritOnly == 0 {
			if bad := ace.Mask & selfForbidden; bad != 0 {
				out = append(out, fmt.Sprintf("grants %s rights 0x%x it must not hold", ace.SID, bad))
			}
		}
		if !isDir {
			continue
		}
		if ace.Flags&aceObjectInherit != 0 {
			// What files created in this directory will grant.
			childForbidden := uint32(fileForbidden)
			if kind == KindLogDir {
				childForbidden = logFileForbidden
			}
			if bad := ace.Mask & childForbidden; bad != 0 {
				out = append(out, fmt.Sprintf("passes %s rights 0x%x to new files", ace.SID, bad))
			}
		}
		if ace.Flags&aceContainerInherit != 0 {
			if bad := ace.Mask & dirForbidden; bad != 0 {
				out = append(out, fmt.Sprintf("passes %s rights 0x%x to new subdirectories", ace.SID, bad))
			}
		}
	}
	return out
}

// CanAppend reports whether a hook running as an interactive user can open the log for append
// and its lock for read-write. On a directory it asks about the files the directory passes its
// entries to; on a file, about the file itself. A matching deny of either bit settles it.
func CanAppend(dacl []ACE, nullDACL bool, ofChildren bool) bool {
	if nullDACL {
		return true
	}
	const need = fileWriteData | fileAppendData
	allowed := false
	for _, ace := range dacl {
		if !coversInteractiveUsers(ace.SID) {
			continue
		}
		applies := ace.Flags&aceInheritOnly == 0
		if ofChildren {
			applies = ace.Flags&aceObjectInherit != 0
		}
		if !applies {
			continue
		}
		switch ace.Type {
		case aceTypeDenied:
			if ace.Mask&(need|genericWrite|genericAll) != 0 {
				return false
			}
		case aceTypeAllowed:
			if ace.Mask&need == need || ace.Mask&(genericWrite|genericAll) != 0 {
				allowed = true
			}
		}
	}
	return allowed
}

// LogDirState is what doctor reports about the log directory.
type LogDirState struct {
	// HooksCanAppend is true when files in the directory, and each existing file of the log
	// family, grant interactive users read and write data.
	HooksCanAppend bool
	// Problems lists grants or owners that would let an ordinary user redirect a SYSTEM write.
	Problems []string
}

// IsLogFamily reports whether name is the runtime log called base, one of its numbered archives,
// or its lock -- the files hooks append to and the privileged writers rotate.
func IsLogFamily(name, base string) bool {
	if strings.EqualFold(name, base) || strings.EqualFold(name, base+".lock") {
		return true
	}
	if len(name) <= len(base)+1 || !strings.EqualFold(name[:len(base)+1], base+".") {
		return false
	}
	_, err := strconv.Atoi(name[len(base)+1:])
	return err == nil
}

// SystemRoot is the directory Beacon owns outright on Windows: the parent of the endpoint base
// directory, %ProgramData%\Beacon.
func SystemRoot(baseDir string) string { return filepath.Dir(baseDir) }
