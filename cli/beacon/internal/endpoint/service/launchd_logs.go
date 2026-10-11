package service

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
)

// Where launchd sends the stdout and stderr of every job Beacon installs.
//
// These used to be fixed names in /tmp (/tmp/<label>.out|err). /tmp is world-writable, so any
// local user could create one of those names before launchd did -- the updater does not run at
// load, so its files did not exist until the first scheduled run -- and a root LaunchDaemon then
// appended its output to a file that user owned, or, through a planted symlink, to any file on
// the system. A user LaunchAgent's /tmp names were just as predictable to every other user.
//
// System daemons now log under /Library/Logs/Beacon, the macOS location for machine-wide
// application logs, created root-owned 0755 before the plist is written so only root can create
// or replace a file in it. It is deliberately not /var/log/beacon-agent: that directory holds the
// runtime log hooks append to (0666 by design) and is what the forwarder packs tail, and daemon
// stderr belongs in neither. User agents log under ~/Library/Logs/Beacon, which only that user
// can write.
var (
	// launchdSystemLogDir is a variable so tests can point it at a temp dir.
	launchdSystemLogDir = "/Library/Logs/Beacon"
	// launchdIsRoot reports whether ownership can and must be forced to root.
	launchdIsRoot = func() bool { return os.Geteuid() == 0 }
)

// LaunchdLogDir is the directory launchd writes Beacon job output to in this mode.
func LaunchdLogDir(userMode bool) (string, error) {
	if !userMode {
		return launchdSystemLogDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Logs", "Beacon"), nil
}

// launchdLogPaths returns a job's StandardOutPath and StandardErrorPath.
func launchdLogPaths(userMode bool, label string) (stdout, stderr string, err error) {
	dir, err := LaunchdLogDir(userMode)
	if err != nil {
		return "", "", err
	}
	if !userMode {
		// launchd paths are POSIX; path.Join keeps them so when this renders on another OS.
		return path.Join(dir, label+".out"), path.Join(dir, label+".err"), nil
	}
	return filepath.Join(dir, label+".out"), filepath.Join(dir, label+".err"), nil
}

// ensureLaunchdLogDir creates the log directory before any plist pointing into it is written, and
// makes sure nothing in it can redirect a job's output.
//
// The system directory is forced to root-owned 0755 when running as root, replacing a symlink in
// its place, so no other account can create or swap a file in it. The job's own two files are
// removed when they are not plain files (a symlink would let launchd append through it) or, for a
// daemon, not owned by root; launchd recreates them on the next start.
func ensureLaunchdLogDir(userMode bool, label string) error {
	dir, err := LaunchdLogDir(userMode)
	if err != nil {
		return err
	}
	mode := os.FileMode(0o755)
	if userMode {
		mode = 0o700
	}
	if fi, err := os.Lstat(dir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			if err := os.Remove(dir); err != nil {
				return fmt.Errorf("remove symlink at log directory %s: %w", dir, err)
			}
		} else if !fi.IsDir() {
			return fmt.Errorf("log directory %s exists and is not a directory", dir)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(dir, mode); err != nil {
		return fmt.Errorf("create log directory %s: %w", dir, err)
	}
	if !userMode && launchdIsRoot() {
		if err := os.Lchown(dir, 0, 0); err != nil {
			return fmt.Errorf("make log directory %s root-owned: %w", dir, err)
		}
	}
	// Chmod after MkdirAll: its mode is masked by umask, and an existing directory keeps its own.
	if err := os.Chmod(dir, mode); err != nil {
		return fmt.Errorf("set permissions on log directory %s: %w", dir, err)
	}
	stdout, stderr, err := launchdLogPaths(userMode, label)
	if err != nil {
		return err
	}
	for _, path := range []string{stdout, stderr} {
		fi, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		untrusted := !fi.Mode().IsRegular()
		if !userMode && launchdIsRoot() {
			if uid, ok := fileOwner(fi); ok && uid != 0 {
				untrusted = true
			}
		}
		if untrusted {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove untrusted log file %s: %w", path, err)
			}
		}
	}
	return nil
}
