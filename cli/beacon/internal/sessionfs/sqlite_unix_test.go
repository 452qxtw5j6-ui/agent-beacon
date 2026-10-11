//go:build !windows

package sessionfs

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// The snapshot carries the -wal file, so rows a runtime has committed but not yet checkpointed are
// still read, and the read-only open leaves nothing beside the user's database.
func TestSQLiteSnapshotReadsCommittedRowsStillInTheWAL(t *testing.T) {
	home := t.TempDir()
	dbPath := filepath.Join(home, ".hermes", "state.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	writer, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	writer.SetMaxOpenConns(1)
	for _, stmt := range []string{
		`PRAGMA journal_mode=WAL`,
		`PRAGMA wal_autocheckpoint=0`,
		`CREATE TABLE messages (body TEXT)`,
		`INSERT INTO messages VALUES ('in the wal')`,
	} {
		if _, err := writer.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	if info, err := os.Stat(dbPath + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("fixture has no WAL to carry: %v", err)
	}

	confine(t, home, os.Getuid())
	snap, err := SQLitePath(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := sql.Open("sqlite", "file:"+snap+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var body string
	if err := reader.QueryRow(`SELECT body FROM messages`).Scan(&body); err != nil || body != "in the wal" {
		t.Fatalf("snapshot read %q, %v", body, err)
	}
	entries, err := os.ReadDir(filepath.Dir(dbPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "state.db", "state.db-wal", "state.db-shm":
		default:
			t.Fatalf("reading the snapshot left %s beside the user's database", entry.Name())
		}
	}
}
