package sessionfs

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A sweep killed mid-copy leaves its snapshot directory behind; the next sweep removes it once it
// is old enough, and leaves recent directories (another process's live sweep) and anything that is
// not a snapshot directory alone.
func TestSnapshotDirRemovesStaleSnapshotsFromKilledSweeps(t *testing.T) {
	parent := t.TempDir()
	now := time.Now()
	mk := func(name string, age time.Duration) string {
		dir := filepath.Join(parent, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "state.vscdb"), []byte("copy"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(dir, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	stale := mk(snapshotDirPrefix+"old", 2*staleSnapshotAge)
	live := mk(snapshotDirPrefix+"live", time.Minute)
	other := mk("unrelated", 2*staleSnapshotAge)

	c := &Confinement{scratchParent: parent}
	dir, err := c.snapshotDir()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("stale snapshot directory survived: %v", err)
	}
	for _, keep := range []string{live, other, dir} {
		if _, err := os.Stat(keep); err != nil {
			t.Errorf("%s was removed: %v", keep, err)
		}
	}
}
