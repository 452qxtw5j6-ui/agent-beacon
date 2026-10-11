//go:build !windows

package writer

// POSIX carries this in the file mode instead: openRuntimeFile creates the runtime log 0666 so
// hooks running as the console user can append to a log the elevated collector created, inside a
// root-owned 0755 directory they cannot add to or remove from. There is no separate ACL step to
// perform, and no separate state to check.

func secureSystemLog(path string) error { return nil }

// inspectSystemLog reports hooks can append because the equivalent guarantee is the file mode,
// which EnsureRuntimeFile already establishes. Reporting otherwise here would make doctor demand a
// fix that does not exist on this platform.
func inspectSystemLog(path string) (LogACLState, error) {
	return LogACLState{HooksCanAppend: true}, nil
}

// GrantCommandHint is empty because there is no grant to run here. Callers use the empty string to
// mean "this remediation does not apply on this platform" rather than printing a Windows command to
// someone on a Mac.
func GrantCommandHint(dir string) string { return "" }
