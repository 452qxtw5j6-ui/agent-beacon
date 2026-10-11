// Package sessionfs is how the session-store collectors read an agent's own session store.
//
// Unconfined, every function is the os call it names, so `beacon endpoint <runtime> sync` and a
// user-mode backfill read exactly what they always read: a person's own symlinks are their
// business.
//
// A system endpoint's install-time backfill is different. It runs as root and reads the console
// user's stores (see runEndpointBackfill in cmd), so anything that user can plant in their home is
// read with root's privileges: a symlink to another user's or root's transcripts, a FIFO that blocks
// the install forever, a device such as /dev/zero. Confine closes that for the duration of the
// sweep. While it is active, a read
//
//   - must name a path inside the console user's home, and is resolved through an os.Root opened on
//     that home, so no symlink, absolute or "..", can lead out of it at any component and there is
//     no window between checking a path and opening it;
//   - opens files non-blocking and checks the opened descriptor, so only regular files and
//     directories are read, never a FIFO, socket or device;
//   - reads only files owned by the console user, which also stops a hard link to someone else's
//     file;
//   - takes a SQLite database through a private snapshot (see SQLitePath), because the driver opens
//     paths itself.
//
// A refused path reads as absent (os.IsNotExist and errors.Is(err, fs.ErrNotExist) both hold), so
// every collector skips it the way it skips a store that is not there, and the refusal is counted so
// the backfill can say what it left out.
package sessionfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// maxRefusalsKept bounds the refusals a confinement remembers by path; the count is exact.
const maxRefusalsKept = 8

// Confinement is an active confinement of session-store reads to one user's home.
type Confinement struct {
	home string
	root *os.Root
	// uid is the owner every file read must have; negative skips the check (Windows).
	uid int

	mu       sync.Mutex
	refused  int
	examples []string
	scratch  string
	// snapshots maps a database path to its copy, so a store that opens one database several times
	// copies it once.
	snapshots map[string]string
}

var active atomic.Pointer[Confinement]

// Confine confines every read through this package to home, admitting only files owned by uid (a
// negative uid skips the ownership check), until Release. Only one confinement can be active.
func Confine(home string, uid int) (*Confinement, error) {
	home = strings.TrimSpace(home)
	if home == "" || !filepath.IsAbs(home) {
		return nil, fmt.Errorf("confine session reads: home %q is not an absolute path", home)
	}
	home = filepath.Clean(home)
	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, fmt.Errorf("confine session reads to %s: %w", home, err)
	}
	c := &Confinement{home: home, root: root, uid: uid}
	if !active.CompareAndSwap(nil, c) {
		_ = root.Close()
		return nil, errors.New("confine session reads: a confinement is already active")
	}
	return c, nil
}

// Release ends the confinement and removes any SQLite snapshots it made.
func (c *Confinement) Release() {
	if c == nil {
		return
	}
	active.CompareAndSwap(c, nil)
	c.DropSnapshots()
	_ = c.root.Close()
}

// Refused reports how many reads the confinement refused and up to a few of their reasons.
func (c *Confinement) Refused() (int, []string) {
	if c == nil {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.refused, append([]string(nil), c.examples...)
}

// DropSnapshots removes the SQLite snapshots made so far. The backfill calls it after each runtime
// so snapshots of one runtime's databases never sit on disk while the next runtime is read.
func (c *Confinement) DropSnapshots() {
	if c == nil {
		return
	}
	c.mu.Lock()
	dir := c.scratch
	c.scratch = ""
	c.snapshots = nil
	c.mu.Unlock()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

// DropSnapshots drops the active confinement's SQLite snapshots; a no-op when unconfined.
func DropSnapshots() { active.Load().DropSnapshots() }

// refuse records a refused read and returns the error the caller sees: a not-exist error, so the
// path is skipped like an absent one.
func (c *Confinement) refuse(op, path, reason string) error {
	c.mu.Lock()
	c.refused++
	if len(c.examples) < maxRefusalsKept {
		c.examples = append(c.examples, path+": "+reason)
	}
	c.mu.Unlock()
	return &fs.PathError{Op: op, Path: path, Err: fs.ErrNotExist}
}

// rel turns an absolute path into one relative to the home, or reports that it is outside.
func (c *Confinement) rel(path string) (string, bool) {
	if !filepath.IsAbs(path) {
		return "", false
	}
	path = filepath.Clean(path)
	if path == c.home {
		return ".", true
	}
	prefix := c.home
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	return strings.TrimPrefix(path, prefix), true
}

// failed turns an error from the root into what the caller sees. A path that is simply absent stays
// absent and is not a refusal; anything else (a link out of the home, a loop) is refused.
func (c *Confinement) failed(op, path string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return &fs.PathError{Op: op, Path: path, Err: fs.ErrNotExist}
	}
	return c.refuse(op, path, err.Error())
}

// check admits a directory, or a regular file the console user owns.
func (c *Confinement) check(op, path string, info fs.FileInfo) error {
	if info.IsDir() {
		return nil
	}
	if !info.Mode().IsRegular() {
		return c.refuse(op, path, "not a regular file ("+info.Mode().Type().String()+")")
	}
	if c.uid >= 0 {
		if owner, ok := ownerUID(info); ok && owner != c.uid {
			return c.refuse(op, path, fmt.Sprintf("owned by uid %d, not the console user (uid %d)", owner, c.uid))
		}
	}
	return nil
}

// Open opens a file or directory for reading.
func Open(path string) (*os.File, error) {
	c := active.Load()
	if c == nil {
		return os.Open(path)
	}
	return c.open("open", path)
}

func (c *Confinement) open(op, path string) (*os.File, error) {
	rel, ok := c.rel(path)
	if !ok {
		return nil, c.refuse(op, path, "outside the console user's home")
	}
	// Non-blocking, so a FIFO is opened and refused rather than waited on for a writer.
	f, err := c.root.OpenFile(rel, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return nil, c.failed(op, path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, c.failed(op, path, err)
	}
	if err := c.check(op, path, info); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// ReadFile reads a whole file.
func ReadFile(path string) ([]byte, error) {
	c := active.Load()
	if c == nil {
		return os.ReadFile(path)
	}
	f, err := c.open("open", path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, &fs.PathError{Op: "read", Path: path, Err: errors.New("is a directory")}
	}
	return io.ReadAll(f)
}

// ReadDir lists a directory sorted by name, as os.ReadDir does.
func ReadDir(path string) ([]fs.DirEntry, error) {
	c := active.Load()
	if c == nil {
		return os.ReadDir(path)
	}
	f, err := c.open("open", path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	kept := entries[:0]
	for _, entry := range entries {
		if c.admitEntry(filepath.Join(path, entry.Name()), entry) {
			kept = append(kept, entry)
		}
	}
	return kept, err
}

// admitEntry decides whether a listed entry is shown to the collector at all, so a planted entry is
// skipped while listing rather than listed and then failing as a session that cannot be read. It
// admits directories, regular files the console user owns, and symlinks that resolve inside the
// home to one of those; everything else is refused here.
func (c *Confinement) admitEntry(path string, entry fs.DirEntry) bool {
	switch {
	case entry.IsDir():
		return true
	case entry.Type()&fs.ModeSymlink != 0:
		rel, ok := c.rel(path)
		if !ok {
			_ = c.refuse("stat", path, "outside the console user's home")
			return false
		}
		info, err := c.root.Stat(rel)
		if err != nil {
			_ = c.failed("stat", path, err)
			return false
		}
		return c.check("stat", path, info) == nil
	default:
		info, err := entry.Info()
		if err != nil {
			return false
		}
		return c.check("lstat", path, info) == nil
	}
}

// Stat describes a path, following symlinks only while they stay inside the home. Confined, a
// path that is neither a directory nor a regular file the console user owns reads as absent.
func Stat(path string) (fs.FileInfo, error) {
	c := active.Load()
	if c == nil {
		return os.Stat(path)
	}
	rel, ok := c.rel(path)
	if !ok {
		return nil, c.refuse("stat", path, "outside the console user's home")
	}
	info, err := c.root.Stat(rel)
	if err != nil {
		return nil, c.failed("stat", path, err)
	}
	if err := c.check("stat", path, info); err != nil {
		return nil, err
	}
	return info, nil
}

// WalkDir walks a tree as filepath.WalkDir does: it does not descend into symlinked directories,
// and the paths it reports are absolute. Confined, the walk runs through the home's os.Root.
func WalkDir(root string, fn fs.WalkDirFunc) error {
	c := active.Load()
	if c == nil {
		return filepath.WalkDir(root, fn)
	}
	rel, ok := c.rel(root)
	if !ok {
		return fn(root, nil, c.refuse("lstat", root, "outside the console user's home"))
	}
	return fs.WalkDir(c.root.FS(), filepath.ToSlash(rel), func(p string, d fs.DirEntry, err error) error {
		abs := filepath.Join(c.home, filepath.FromSlash(p))
		if err != nil {
			err = c.failed("walk", abs, err)
		} else if d != nil && !c.admitEntry(abs, d) {
			return nil
		}
		return fn(abs, d, err)
	})
}

// SQLitePath returns the path to hand the SQLite driver for the database at path.
//
// Unconfined it is path itself. Confined, the driver cannot be trusted with the user's path: it
// opens it, and its -wal and -shm files, by name, following any symlink, and in read-only mode it
// still creates a -shm file beside the database. So the database and its -wal file are read through
// the confinement into a private directory, and the driver opens that copy; DropSnapshots removes
// it. A WAL file that is refused is left out, which loses at most the writes not yet checkpointed.
func SQLitePath(path string) (string, error) {
	c := active.Load()
	if c == nil {
		return path, nil
	}
	return c.snapshotSQLite(path)
}

func (c *Confinement) snapshotSQLite(path string) (string, error) {
	c.mu.Lock()
	cached, ok := c.snapshots[path]
	c.mu.Unlock()
	if ok {
		return cached, nil
	}
	src, err := c.open("open", path)
	if err != nil {
		return "", err
	}
	defer src.Close()
	if info, err := src.Stat(); err != nil {
		return "", err
	} else if info.IsDir() {
		return "", c.refuse("open", path, "a directory, not a database")
	}
	dir, err := c.snapshotDir()
	if err != nil {
		return "", err
	}
	target, err := os.MkdirTemp(dir, "db-")
	if err != nil {
		return "", err
	}
	copyPath := filepath.Join(target, filepath.Base(path))
	if err := copyInto(copyPath, src); err != nil {
		return "", err
	}
	if wal, err := c.open("open", path+"-wal"); err == nil {
		err = copyInto(copyPath+"-wal", wal)
		_ = wal.Close()
		if err != nil {
			return "", err
		}
	}
	c.mu.Lock()
	if c.snapshots == nil {
		c.snapshots = map[string]string{}
	}
	c.snapshots[path] = copyPath
	c.mu.Unlock()
	return copyPath, nil
}

func (c *Confinement) snapshotDir() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.scratch != "" {
		return c.scratch, nil
	}
	dir, err := os.MkdirTemp("", "beacon-backfill-sqlite-")
	if err != nil {
		return "", fmt.Errorf("create SQLite snapshot directory: %w", err)
	}
	c.scratch = dir
	return dir, nil
}

func copyInto(path string, src *os.File) error {
	dst, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}
