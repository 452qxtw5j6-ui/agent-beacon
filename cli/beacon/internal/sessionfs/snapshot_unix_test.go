//go:build !windows

package sessionfs

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// walStore is a WAL-mode database whose rows sit in the WAL, never checkpointed, with the writer
// connection kept open so a test can checkpoint and write while a snapshot is being taken.
func walStore(t *testing.T, home string) (string, *sql.DB) {
	t.Helper()
	path := filepath.Join(home, ".local", "share", "opencode", "opencode.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	exec(t, db, `PRAGMA journal_mode=WAL`, `PRAGMA wal_autocheckpoint=0`, `CREATE TABLE messages (body TEXT)`, `INSERT INTO messages VALUES ('a')`)
	return path, db
}

func exec(t *testing.T, db *sql.DB, stmts ...string) {
	t.Helper()
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

// checkpointAndWrite is the race the snapshot must survive: everything moves from the WAL into the
// database, the WAL restarts with new salts, and a new row lands in the fresh WAL. A copy of the old
// database paired with the new WAL has neither the table nor its first row.
func checkpointAndWrite(t *testing.T, db *sql.DB, body string) {
	exec(t, db, `PRAGMA wal_checkpoint(TRUNCATE)`, `INSERT INTO messages VALUES ('`+body+`')`)
}

func withBetweenCopies(t *testing.T, fn func(string)) {
	t.Helper()
	old := betweenSnapshotCopies
	t.Cleanup(func() { betweenSnapshotCopies = old })
	betweenSnapshotCopies = fn
}

func readBodies(t *testing.T, path string) []string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT body FROM messages ORDER BY rowid`)
	if err != nil {
		t.Fatalf("snapshot is not a consistent database: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			t.Fatal(err)
		}
		out = append(out, body)
	}
	return out
}

func TestSQLiteSnapshotRetriesWhenTheWALRestartsBetweenCopies(t *testing.T) {
	home := t.TempDir()
	path, db := walStore(t, home)
	calls := 0
	withBetweenCopies(t, func(string) {
		calls++
		if calls == 1 {
			checkpointAndWrite(t, db, "b")
		}
	})
	confine(t, home, os.Getuid())

	snap, err := SQLitePath(path)
	if err != nil {
		t.Fatalf("SQLitePath: %v", err)
	}
	if calls != 2 {
		t.Fatalf("copied %d times, want a retry after the WAL restarted", calls)
	}
	if got := readBodies(t, snap); strings.Join(got, ",") != "a,b" {
		t.Fatalf("snapshot rows = %v, want a,b", got)
	}
}

func TestSQLiteSnapshotThatNeverSettlesIsRefused(t *testing.T) {
	home := t.TempDir()
	path, db := walStore(t, home)
	calls := 0
	withBetweenCopies(t, func(string) {
		calls++
		checkpointAndWrite(t, db, "busy")
	})
	c := confine(t, home, os.Getuid())

	_, err := SQLitePath(path)
	requireRefusedAsAbsent(t, "a store that changes during every copy", err)
	if calls != snapshotAttempts {
		t.Fatalf("copied %d times, want %d attempts", calls, snapshotAttempts)
	}
	if n, examples := c.Refused(); n != 1 || !strings.Contains(examples[0], "changed during every copy attempt") {
		t.Fatalf("refusals = %d %v", n, examples)
	}
	if left, _ := filepath.Glob(filepath.Join(c.scratch, "db-*")); len(left) != 0 {
		t.Fatalf("failed attempts left copies behind: %v", left)
	}
}

func TestSQLiteSnapshotRefusesAStoreOverTheSizeCap(t *testing.T) {
	old := maxSnapshotBytes
	t.Cleanup(func() { maxSnapshotBytes = old })
	maxSnapshotBytes = 64 << 10

	home := t.TempDir()
	big := filepath.Join(home, ".cursor", "state.vscdb")
	mustWrite(t, big, strings.Repeat("x", 80<<10))
	walHeavy := filepath.Join(home, ".hermes", "state.db")
	mustWrite(t, walHeavy, strings.Repeat("x", 40<<10))
	mustWrite(t, walHeavy+"-wal", strings.Repeat("w", 40<<10))
	small := filepath.Join(home, ".local", "share", "opencode", "opencode.db")
	mustWrite(t, small, "small")

	scratch := filepath.Join(t.TempDir(), "state", "backfill-snapshots")
	c, err := Confine(home, os.Getuid(), Options{ScratchDir: scratch})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Release)

	for _, path := range []string{big, walHeavy} {
		_, err := SQLitePath(path)
		requireRefusedAsAbsent(t, path, err)
	}
	if got := TakeOversized(); len(got) != 2 || got[0] != big || got[1] != walHeavy {
		t.Fatalf("TakeOversized = %v", got)
	}
	if got := TakeOversized(); len(got) != 0 {
		t.Fatalf("TakeOversized did not forget: %v", got)
	}
	if _, examples := c.Refused(); len(examples) != 2 || !strings.Contains(examples[0], "a system backfill copies") {
		t.Fatalf("refusal reason = %v", examples)
	}

	// A store under the cap is copied into the configured scratch directory, private to root.
	snap, err := SQLitePath(small)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(snap, scratch+string(filepath.Separator)) {
		t.Fatalf("snapshot %s is not under the scratch directory %s", snap, scratch)
	}
	for _, dir := range []string{scratch, c.scratch} {
		if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v, want a 0700 directory", dir, info, err)
		}
	}
	DropSnapshots()
	if left, _ := os.ReadDir(scratch); len(left) != 0 {
		t.Fatalf("DropSnapshots left %v", left)
	}
}
