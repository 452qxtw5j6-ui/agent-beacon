// Package activesession records, per runtime and working directory, the agent session a hook saw
// last, so `beacon share --current` can name "this session" from inside an agent without being told
// its id.
//
// The record is a small local file, `~/.beacon/endpoint/active-sessions.json` (0600 under a 0700
// directory). The hook adapter writes it as a side effect of writing an event; the CLI only reads
// it. It never leaves the machine and it holds identifiers and paths only -- a session id, a
// harness name, a working directory and a timestamp -- never content.
//
// Writes are cheap enough for the hook path: the file is bounded (MaxEntries), stale entries are
// pruned on every write (MaxAge), an entry that has not changed is only rewritten once its
// timestamp is RefreshInterval old, and every write is an atomic rename under an advisory lock.
package activesession

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve/filelock"
)

const (
	// FileName is the record's name under the endpoint base directory.
	FileName = "active-sessions.json"
	// PathEnv overrides where the record lives (tests, unusual homes).
	PathEnv = "BEACON_ACTIVE_SESSIONS_FILE"
	// MaxEntries bounds the record; the oldest entries go first.
	MaxEntries = 256
	// MaxAge is how long an entry is kept after it was last seen.
	MaxAge = 14 * 24 * time.Hour
	// RefreshInterval is how stale an unchanged entry's timestamp may get before it is rewritten.
	RefreshInterval = time.Minute

	schemaVersion = "beacon.active_sessions.v1"
)

// Entry is the session a runtime last reported in one working directory.
type Entry struct {
	Harness          string    `json:"harness"`
	SessionID        string    `json:"session_id"`
	WorkingDirectory string    `json:"working_directory"`
	LastSeen         time.Time `json:"last_seen"`
}

type document struct {
	SchemaVersion string  `json:"schema_version"`
	Sessions      []Entry `json:"sessions"`
}

// DefaultPath is BEACON_ACTIVE_SESSIONS_FILE, or ~/.beacon/endpoint/active-sessions.json.
func DefaultPath() string {
	if p := strings.TrimSpace(os.Getenv(PathEnv)); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".beacon", "endpoint", FileName)
}

// CleanDir is the form working directories are compared in.
func CleanDir(dir string) string {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return ""
	}
	return filepath.Clean(dir)
}

func entryKey(harness, dir string) string { return harness + "\x00" + dir }

// Read returns every entry in the record at path, newest first. A missing or unreadable record
// reads as empty.
func Read(path string) ([]Entry, error) {
	doc, err := load(path)
	if err != nil {
		return nil, err
	}
	out := append([]Entry(nil), doc.Sessions...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out, nil
}

// Lookup returns the newest entry for dir, limited to harness when it is not empty, that was seen
// within maxAge (0 for MaxAge).
func Lookup(path, harness, dir string, maxAge time.Duration, now time.Time) (Entry, bool) {
	entries, err := Read(path)
	if err != nil {
		return Entry{}, false
	}
	if maxAge <= 0 {
		maxAge = MaxAge
	}
	dir = CleanDir(dir)
	for _, e := range entries {
		if e.WorkingDirectory != dir || (harness != "" && e.Harness != harness) {
			continue
		}
		if now.Sub(e.LastSeen) > maxAge {
			continue
		}
		return e, true
	}
	return Entry{}, false
}

// Record notes that harness reported session in dir at now. It is a no-op when any of the three is
// empty, and rewrites the file only when the entry changed or its timestamp is RefreshInterval old.
func Record(path, harness, session, dir string, now time.Time) error {
	harness, session, dir = strings.TrimSpace(harness), strings.TrimSpace(session), CleanDir(dir)
	if path == "" || harness == "" || session == "" || dir == "" {
		return nil
	}
	return update(path, now, func(doc *document) bool {
		for i, e := range doc.Sessions {
			if entryKey(e.Harness, e.WorkingDirectory) != entryKey(harness, dir) {
				continue
			}
			if e.SessionID == session && now.Sub(e.LastSeen) < RefreshInterval {
				return false
			}
			doc.Sessions[i].SessionID = session
			doc.Sessions[i].LastSeen = now.UTC()
			return true
		}
		doc.Sessions = append(doc.Sessions, Entry{Harness: harness, SessionID: session, WorkingDirectory: dir, LastSeen: now.UTC()})
		return true
	})
}

func load(path string) (document, error) {
	doc := document{SchemaVersion: schemaVersion}
	if path == "" {
		return doc, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return doc, nil
		}
		return doc, err
	}
	if len(data) == 0 {
		return doc, nil
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		// A damaged record is replaced rather than trusted; it holds nothing that cannot be
		// rebuilt by the next hook.
		return document{SchemaVersion: schemaVersion}, nil
	}
	doc.SchemaVersion = schemaVersion
	return doc, nil
}

func update(path string, now time.Time, mutate func(*document) bool) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	lockFile, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	// The lock file is never written, so closing it loses nothing; its error is reported only
	// when nothing else went wrong.
	defer func() {
		if cerr := lockFile.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	lock, err := filelock.Exclusive(lockFile)
	if err != nil {
		return err
	}
	defer lock.Release()

	doc, err := load(path)
	if err != nil {
		return err
	}
	changed := mutate(&doc)
	if prune(&doc, now) {
		changed = true
	}
	if !changed {
		return nil
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+FileName+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// prune drops entries older than MaxAge and trims both lists to their bounds, oldest first.
func prune(doc *document, now time.Time) bool {
	changed := false
	kept := doc.Sessions[:0]
	for _, e := range doc.Sessions {
		if now.Sub(e.LastSeen) <= MaxAge {
			kept = append(kept, e)
		} else {
			changed = true
		}
	}
	doc.Sessions = kept
	if len(doc.Sessions) > MaxEntries {
		sort.SliceStable(doc.Sessions, func(i, j int) bool { return doc.Sessions[i].LastSeen.After(doc.Sessions[j].LastSeen) })
		doc.Sessions = doc.Sessions[:MaxEntries]
		changed = true
	}
	return changed
}
