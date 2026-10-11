//go:build windows

package writer

import (
	"os"
	"path/filepath"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/sysacl"
)

// secureSystemLog gives a machine-wide log directory the one ACL under which hooks can append and
// nobody but SYSTEM and Administrators can change what is in it.
//
// This is the Windows counterpart to the 0666 runtime log in a root-owned 0755 directory on POSIX,
// and it exists for the same reason: a system-mode collector runs as LocalSystem and creates the
// log, while hooks run as the person at the keyboard and append to it. %ProgramData%
// subdirectories inherit an ACL where ordinary users cannot write existing files, so without a
// grant every hook write fails with access denied -- quietly, because status and doctor describe
// the collector rather than the hooks exporting to it.
//
// The grant used to be Modify for INTERACTIVE on the directory, recursively. That let any logged-on
// user delete the log and its archives, empty the directory, turn it into a junction and plant
// links named runtime.jsonl, runtime.jsonl.N or the lock -- so the collector, running as SYSTEM,
// would create or append to a file of the user's choosing. sysacl.LogDirDACL replaces it: the
// directory is owned by Administrators with inheritance disabled, SYSTEM and Administrators have
// full control, Users read and traverse, and INTERACTIVE holds read and write data on the files
// in the directory only, through an inherit-only entry. Users cannot create, delete or rename
// anything there, and cannot change the security of the files they append to.
//
// Because users cannot create files, the log and its lock are created here, by the elevated
// install, so a hook always finds them. Rotation is the privileged writers' job on Windows (the
// collector and the CLI running as SYSTEM or an administrator); a hook that finds the log over
// its size limit appends anyway and leaves the rename to them.
func secureSystemLog(path string) error {
	dir := filepath.Dir(path)
	if err := sysacl.SecureLogDir(dir, filepath.Base(path)); err != nil {
		return err
	}
	// Created after the directory ACL is in place, so both inherit the append grant.
	lock, err := openRuntimeFile(path+".lock", os.O_CREATE|os.O_RDWR)
	if err != nil {
		return err
	}
	_ = lock.Close()
	f, err := openRuntimeFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY)
	if err != nil {
		return err
	}
	return f.Close()
}

// inspectSystemLog reports whether hooks can append and what, if anything, grants more.
//
// Read through the security APIs rather than by attempting a write: doctor runs elevated, so a test
// write would succeed regardless and report healthy for exactly the configuration that is broken.
// Read by SID rather than by parsing icacls output, which names accounts in the display language.
func inspectSystemLog(path string) (LogACLState, error) {
	state, err := sysacl.InspectLogDir(filepath.Dir(path), filepath.Base(path))
	return LogACLState{HooksCanAppend: state.HooksCanAppend, Problems: state.Problems}, err
}

// GrantCommandHint is the command that restores the log directory ACL.
//
// It used to print an icacls grant. The ACL is now several entries, an owner, inheritance turned
// off and a reset of the log family's files, and printing a hand-run equivalent would be advice
// that drifts from the implementation. doctor --fix runs the same code the install does.
func GrantCommandHint(dir string) string {
	return "beacon endpoint doctor --system --fix (from an elevated shell)"
}
