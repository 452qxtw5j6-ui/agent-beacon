package activesession

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestRecordAndLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint", FileName)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	if err := Record(path, "claude_code", "s1", "/work/repo/", now); err != nil {
		t.Fatal(err)
	}
	if err := Record(path, "codex_cli", "c1", "/work/repo", now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, ok := Lookup(path, "", "/work/repo", 0, now.Add(2*time.Second))
	if !ok || got.SessionID != "c1" {
		t.Fatalf("newest in dir = %+v, %v", got, ok)
	}
	got, ok = Lookup(path, "claude_code", "/work/repo", 0, now.Add(2*time.Second))
	if !ok || got.SessionID != "s1" {
		t.Fatalf("claude in dir = %+v, %v", got, ok)
	}
	if _, ok := Lookup(path, "", "/work/other", 0, now); ok {
		t.Fatal("other directory matched")
	}
	if _, ok := Lookup(path, "", "/work/repo", time.Hour, now.Add(2*time.Hour)); ok {
		t.Fatal("stale entry matched")
	}
	// A new session in the same directory replaces the old one for that runtime.
	if err := Record(path, "claude_code", "s2", "/work/repo", now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	entries, _ := Read(path)
	if len(entries) != 2 || entries[0].SessionID != "s2" {
		t.Fatalf("entries = %+v", entries)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode = %v, %v", info.Mode(), err)
		}
		dir, _ := os.Stat(filepath.Dir(path))
		if dir.Mode().Perm() != 0o700 {
			t.Fatalf("dir mode = %v", dir.Mode())
		}
	}
}

func TestRecordSkipsUnchangedWritesAndIgnoresEmptyFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, args := range [][3]string{{"", "s", "/d"}, {"h", "", "/d"}, {"h", "s", ""}} {
		if err := Record(path, args[0], args[1], args[2], now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("record written for empty fields: %v", err)
	}
	if err := Record(path, "h", "s", "/d", now); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if err := Record(path, "h", "s", "/d", now.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("unchanged entry rewritten inside the refresh interval")
	}
	if err := Record(path, "h", "s", "/d", now.Add(2*RefreshInterval)); err != nil {
		t.Fatal(err)
	}
	entries, _ := Read(path)
	if !entries[0].LastSeen.Equal(now.Add(2 * RefreshInterval)) {
		t.Fatalf("last seen not refreshed: %v", entries[0].LastSeen)
	}
}

func TestRecordPrunesAndBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := Record(path, "h", "old", "/old", start); err != nil {
		t.Fatal(err)
	}
	now := start.Add(MaxAge + time.Hour)
	for i := 0; i < MaxEntries+10; i++ {
		if err := Record(path, "h", "s", filepath.Join("/d", string(rune('a'+i%26)), time.Duration(i).String()), now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := Read(path)
	if len(entries) != MaxEntries {
		t.Fatalf("len = %d", len(entries))
	}
	for _, e := range entries {
		if e.SessionID == "old" {
			t.Fatal("stale entry kept")
		}
	}
}

func TestDamagedRecordIsReplaced(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if entries, err := Read(path); err != nil || len(entries) != 0 {
		t.Fatalf("damaged read = %v, %v", entries, err)
	}
	if err := Record(path, "h", "s", "/d", time.Now()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &doc); err != nil || doc["schema_version"] != schemaVersion {
		t.Fatalf("doc = %s", data)
	}
}

func TestMarkShareRequestedOncePerSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	first, err := MarkShareRequested(path, "claude_code", "s1", now)
	if err != nil || !first {
		t.Fatalf("first = %v, %v", first, err)
	}
	again, err := MarkShareRequested(path, "claude_code", "s1", now.Add(time.Hour))
	if err != nil || again {
		t.Fatalf("again = %v, %v", again, err)
	}
	other, _ := MarkShareRequested(path, "codex_cli", "s1", now)
	if !other {
		t.Fatal("another runtime's session with the same id was deduplicated")
	}
	// Active-session writes keep the marks.
	if err := Record(path, "claude_code", "s1", "/d", now); err != nil {
		t.Fatal(err)
	}
	if again, _ := MarkShareRequested(path, "claude_code", "s1", now); again {
		t.Fatal("mark lost after a Record")
	}
}

func TestUnmarkShareRequestedRemovesOnlyItsOwnMark(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	first := time.Date(2026, 10, 1, 10, 0, 0, 123456789, time.UTC)
	if ok, err := MarkShareRequested(path, "claude_code", "s1", first); err != nil || !ok {
		t.Fatalf("mark = %v %v", ok, err)
	}
	// Another mark time is not this one: left alone.
	if err := UnmarkShareRequested(path, "claude_code", "s1", first.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := MarkShareRequested(path, "claude_code", "s1", first); ok {
		t.Fatal("a different mark time removed the mark")
	}
	if err := UnmarkShareRequested(path, "claude_code", "s1", first); err != nil {
		t.Fatal(err)
	}
	if ok, err := MarkShareRequested(path, "claude_code", "s1", first.Add(time.Minute)); err != nil || !ok {
		t.Fatalf("after unmark, mark = %v %v", ok, err)
	}
}
