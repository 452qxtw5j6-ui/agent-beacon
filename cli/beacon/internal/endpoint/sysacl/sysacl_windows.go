//go:build windows

package sysacl

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SecureSystemTree resets %ProgramData%\Beacon (root) and everything beneath it.
//
// root is created if missing and replaced if it is a link. It is then owned by Administrators and
// given the protected TreeDACL, unconditionally: an existing directory -- including one a
// non-administrator created before the package was installed, and so owns -- is reset, not
// trusted. Below it, every link (junction, symbolic link, mount point) and every hard-linked file
// is removed, since Beacon creates neither and both redirect a privileged write elsewhere; and
// every object whose owner or DACL fails Problems is given Administrators ownership and exactly
// what it would inherit. Objects that are already safe are left alone, so a stricter ACL an
// administrator set deliberately survives.
//
// Paths in skip (the log directory, which SecureLogDir owns) are not descended into.
//
// Everything is set through a handle opened without following reparse points, and with
// SetKernelObjectSecurity, which writes exactly the descriptor given and does not walk or
// re-propagate to children by path the way SetNamedSecurityInfo does. A pass that resets security
// must never be steerable onto a path outside the tree.
func SecureSystemTree(root string, skip ...string) error {
	return withPrivileges(func() error {
		h, err := ensureRealDir(root)
		if err != nil {
			return err
		}
		err = setSecurity(h, true, TreeDACL())
		windows.CloseHandle(h)
		if err != nil {
			return fmt.Errorf("secure %s: %w", root, err)
		}
		return walkTree(root, TreeDACL(), skipSet(skip))
	})
}

// SecureLogDir gives the system log directory its ACL, and resets the runtime log family in it.
//
// dir is created if missing and replaced if it is a link. It is owned by Administrators with the
// protected LogDirDACL. Of its direct children, every link is removed (a link in a directory a
// SYSTEM process writes to is the attack this exists to close); every file of the base log's
// family that is hard-linked elsewhere is removed; and every other file of the family is given
// Administrators ownership and exactly the inherited DACL a newly rotated log gets. Anything else
// in the directory is left as it is: a log directory an operator pointed elsewhere may hold their
// own files, and no Beacon process writes them.
func SecureLogDir(dir, base string) error {
	return withPrivileges(func() error {
		h, err := ensureRealDir(dir)
		if err != nil {
			return err
		}
		err = setSecurity(h, true, LogDirDACL())
		windows.CloseHandle(h)
		if err != nil {
			return fmt.Errorf("secure %s: %w", dir, err)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		inherited := InheritedDACL(LogDirDACL(), false)
		var errs []error
		for _, entry := range entries {
			child := filepath.Join(dir, entry.Name())
			family := IsLogFamily(entry.Name(), base)
			h, info, err := openNoFollow(child)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil {
				errs = append(errs, fmt.Errorf("open %s: %w", child, err))
				continue
			}
			link := info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
			dirEntry := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
			hardLinked := !dirEntry && info.NumberOfLinks > 1
			switch {
			case link || (family && hardLinked):
				windows.CloseHandle(h)
				if err := os.Remove(child); err != nil && !errors.Is(err, fs.ErrNotExist) {
					errs = append(errs, fmt.Errorf("remove the link %s: %w", child, err))
				}
			case family && !dirEntry:
				if err := setSecurity(h, false, inherited); err != nil {
					errs = append(errs, fmt.Errorf("secure %s: %w", child, err))
				}
				windows.CloseHandle(h)
			default:
				windows.CloseHandle(h)
			}
		}
		return errors.Join(errs...)
	})
}

// InspectLogDir reads the log directory and its log family and assesses them. Read-only; it needs
// no privilege beyond READ_CONTROL, which Users hold.
func InspectLogDir(dir, base string) (LogDirState, error) {
	var state LogDirState
	obj, isLink, err := readObject(dir)
	if err != nil {
		return state, err
	}
	if isLink {
		state.Problems = append(state.Problems, dir+" is a link, so writes to it land wherever it points")
		return state, nil
	}
	for _, p := range Problems(obj, KindLogDir) {
		state.Problems = append(state.Problems, dir+": "+p)
	}
	state.HooksCanAppend = CanAppend(obj.DACL, obj.NullDACL, true)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return state, err
	}
	for _, entry := range entries {
		if !IsLogFamily(entry.Name(), base) {
			continue
		}
		child := filepath.Join(dir, entry.Name())
		fobj, link, err := readObject(child)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return state, err
		}
		if link {
			state.Problems = append(state.Problems, child+" is a link, so writes to it land wherever it points")
			continue
		}
		for _, p := range Problems(fobj, KindLogFile) {
			state.Problems = append(state.Problems, child+": "+p)
		}
		// Only the files a hook opens decide whether it can write; an archive it cannot append to
		// is how it should be once rotation stops granting more.
		if strings.EqualFold(entry.Name(), base) || strings.EqualFold(entry.Name(), base+".lock") {
			if !CanAppend(fobj.DACL, fobj.NullDACL, false) {
				state.HooksCanAppend = false
			}
		}
	}
	return state, nil
}

// InspectTree reports the problems on root itself, for tests and diagnostics.
func InspectTree(path string, kind Kind) ([]string, error) {
	obj, link, err := readObject(path)
	if err != nil {
		return nil, err
	}
	if link {
		return []string{path + " is a link"}, nil
	}
	return Problems(obj, kind), nil
}

// ReadObject returns the owner and DACL of path without following a link, for tests.
func ReadObject(path string) (Object, error) {
	obj, _, err := readObject(path)
	return obj, err
}

func walkTree(dir string, dirDACL []ACE, skip map[string]bool) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		child := filepath.Join(dir, entry.Name())
		if skip[normPath(child)] {
			continue
		}
		h, info, err := openNoFollow(child)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("open %s: %w", child, err))
			continue
		}
		isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (!isDir && info.NumberOfLinks > 1) {
			windows.CloseHandle(h)
			if err := os.Remove(child); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("remove the link %s: %w", child, err))
			}
			continue
		}
		kind := KindFile
		if isDir {
			kind = KindDir
		}
		obj, err := objectFromHandle(h)
		if err == nil && len(Problems(obj, kind)) > 0 {
			err = setSecurity(h, false, InheritedDACL(dirDACL, isDir))
			if err == nil {
				obj, err = objectFromHandle(h)
			}
		}
		windows.CloseHandle(h)
		if err != nil {
			errs = append(errs, fmt.Errorf("secure %s: %w", child, err))
			continue
		}
		if isDir {
			if err := walkTree(child, obj.DACL, skip); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// ensureRealDir opens path as a directory that is not a link, creating it if missing and removing a
// link found in its place. A few attempts, because removing a link and creating the directory are
// two steps; the parent is expected to be one ordinary users cannot write (the tree root's parent
// is %ProgramData%, whose existing entries they cannot replace), so a lost race means something is
// actively interfering and the install should stop rather than loop.
func ensureRealDir(path string) (windows.Handle, error) {
	for attempt := 0; attempt < 3; attempt++ {
		h, info, err := openNoFollow(path)
		if errors.Is(err, fs.ErrNotExist) {
			if err := os.MkdirAll(path, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
				return windows.InvalidHandle, fmt.Errorf("create %s: %w", path, err)
			}
			continue
		}
		if err != nil {
			return windows.InvalidHandle, fmt.Errorf("open %s: %w", path, err)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			windows.CloseHandle(h)
			// Removes the link itself, never what it points to.
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return windows.InvalidHandle, fmt.Errorf("%s is a link and could not be removed: %w", path, err)
			}
			continue
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			windows.CloseHandle(h)
			return windows.InvalidHandle, fmt.Errorf("%s exists and is not a directory", path)
		}
		return h, nil
	}
	return windows.InvalidHandle, fmt.Errorf("%s kept changing while it was being secured", path)
}

// openNoFollow opens the object at path itself -- a link rather than its target -- with the rights
// needed to read and replace its owner and DACL.
func openNoFollow(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, info, err
	}
	h, err := windows.CreateFile(p,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return windows.InvalidHandle, info, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return windows.InvalidHandle, info, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	return h, info, nil
}

// readObject reads path's security without following a link and without asking for write access.
func readObject(path string) (Object, bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return Object{}, false, err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return Object{}, false, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return Object{}, false, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	obj, err := objectFromHandle(h)
	return obj, info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, err
}

func objectFromHandle(h windows.Handle) (Object, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return Object{}, fmt.Errorf("read the security descriptor: %w", err)
	}
	var obj Object
	if owner, _, err := sd.Owner(); err == nil && owner != nil {
		obj.Owner = owner.String()
	}
	if control, _, err := sd.Control(); err == nil {
		obj.Protected = control&windows.SE_DACL_PROTECTED != 0
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return Object{}, fmt.Errorf("read the DACL: %w", err)
	}
	if dacl == nil {
		obj.NullDACL = true
		return obj, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return Object{}, fmt.Errorf("read access control entry %d: %w", i, err)
		}
		// ACCESS_ALLOWED and ACCESS_DENIED entries carry the SID at the same offset. Other types
		// (object and callback entries) lay out differently; they never appear on files Beacon
		// creates, so one is recorded without a SID, which Problems treats as untrusted and resets.
		entry := ACE{Type: ace.Header.AceType, Flags: ace.Header.AceFlags, Mask: uint32(ace.Mask)}
		if entry.Type == aceTypeAllowed || entry.Type == aceTypeDenied {
			entry.SID = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		obj.DACL = append(obj.DACL, entry)
	}
	runtime.KeepAlive(sd)
	return obj, nil
}

// setSecurity replaces the owner and DACL on h. A protected descriptor stops inheritance from the
// parent; an unprotected one carries the inherited entries computed by InheritedDACL.
func setSecurity(h windows.Handle, protected bool, dacl []ACE) error {
	sd, err := windows.SecurityDescriptorFromString(SDDL(sidAdministrators, protected, dacl))
	if err != nil {
		return fmt.Errorf("build the security descriptor: %w", err)
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	err = windows.SetKernelObjectSecurity(h, info, sd)
	runtime.KeepAlive(sd)
	return err
}

// withPrivileges runs fn on a locked OS thread impersonating this process with SeRestorePrivilege,
// SeTakeOwnershipPrivilege and SeBackupPrivilege enabled.
//
// They are what let an administrator take back a directory someone else created and locked:
// without them, a pre-created %ProgramData%\Beacon whose owner denied Administrators everything
// could not be opened for WRITE_OWNER at all. Enabled on an impersonation token for this thread
// only, so the rest of the process never runs with them. A privilege the token does not hold is
// simply not enabled, and fn runs anyway: an ordinary elevated install needs none of them.
func withPrivileges(fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			done <- fn()
			return
		}
		enablePrivileges("SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeBackupPrivilege")
		err := fn()
		if rerr := windows.RevertToSelf(); rerr != nil {
			// Leave the thread locked: a goroutine that exits while locked takes its thread with
			// it, so the impersonation token cannot leak to other goroutines.
			done <- errors.Join(err, fmt.Errorf("revert impersonation: %w", rerr))
			return
		}
		runtime.UnlockOSThread()
		done <- err
	}()
	return <-done
}

func enablePrivileges(names ...string) {
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, true, &token); err != nil {
		return
	}
	defer token.Close()
	for _, name := range names {
		var luid windows.LUID
		p, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		if err := windows.LookupPrivilegeValue(nil, p, &luid); err != nil {
			continue
		}
		privileges := windows.Tokenprivileges{PrivilegeCount: 1}
		privileges.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)
	}
}

func skipSet(paths []string) map[string]bool {
	out := make(map[string]bool, len(paths))
	for _, p := range paths {
		if p != "" {
			out[normPath(p)] = true
		}
	}
	return out
}

func normPath(p string) string { return strings.ToLower(filepath.Clean(p)) }
