package updatecheck

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/testenv"
)

func TestCacheRoundTripsWithPrivateModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "endpoint")
	path := filepath.Join(dir, CacheFile)
	want := Cache{LatestVersion: "v0.0.12", ReleaseURL: "https://example.test/r", LastCheckedAt: time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)}
	if err := SaveCache(path, want); err != nil {
		t.Fatal(err)
	}
	if got := LoadCache(path); got != want {
		t.Fatalf("LoadCache = %#v, want %#v", got, want)
	}
	if testenv.HasPOSIXFileModes() {
		for p, mode := range map[string]os.FileMode{dir: 0o700, path: 0o600} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != mode {
				t.Fatalf("%s mode = %o, want %o", p, info.Mode().Perm(), mode)
			}
		}
	}
}

func TestLoadCacheTreatsMissingOrCorruptAsEmpty(t *testing.T) {
	dir := t.TempDir()
	if got := LoadCache(filepath.Join(dir, "missing.json")); got != (Cache{}) {
		t.Fatalf("missing cache = %#v", got)
	}
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := LoadCache(bad); got != (Cache{}) {
		t.Fatalf("corrupt cache = %#v", got)
	}
}

func TestCacheStale(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name    string
		checked time.Time
		want    bool
	}{
		{name: "never", want: true},
		{name: "recent", checked: now.Add(-time.Hour), want: false},
		{name: "expired", checked: now.Add(-CacheTTL), want: true},
		{name: "future clock", checked: now.Add(time.Hour), want: true},
	} {
		if got := (Cache{LastCheckedAt: tt.checked}).Stale(now); got != tt.want {
			t.Fatalf("%s: Stale = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCacheNotice(t *testing.T) {
	cache := Cache{LatestVersion: "v0.0.12", ReleaseURL: "https://example.test/r"}
	if got := cache.Notice("v0.0.10"); !got.UpdateAvailable || got.LatestVersion != "v0.0.12" || got.ReleaseURL != "https://example.test/r" {
		t.Fatalf("older current: %#v", got)
	}
	for _, current := range []string{"v0.0.12", "v0.1.0", "dev", "v0.0.10+local"} {
		if cache.Notice(current).UpdateAvailable {
			t.Fatalf("current %q: notice offered an update", current)
		}
	}
	if (Cache{}).Notice("v0.0.10").UpdateAvailable {
		t.Fatal("empty cache offered an update")
	}
}

func TestCacheRecordKeepsTheLastReleaseOnFailure(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	cache := Cache{LatestVersion: "v0.0.11", ReleaseURL: "old"}
	failed := cache.Record(Result{}, errors.New("rate limited"), now)
	if failed.LatestVersion != "v0.0.11" || failed.ReleaseURL != "old" || !failed.LastCheckedAt.Equal(now) {
		t.Fatalf("failed record = %#v", failed)
	}
	ok := cache.Record(Result{LatestVersion: "v0.0.12", ReleaseURL: "new"}, nil, now)
	if ok.LatestVersion != "v0.0.12" || ok.ReleaseURL != "new" {
		t.Fatalf("successful record = %#v", ok)
	}
}

func TestDisabled(t *testing.T) {
	for _, tt := range []struct {
		env  map[string]string
		want bool
	}{
		{env: map[string]string{}, want: false},
		{env: map[string]string{DisableEnv: "1"}, want: false},
		{env: map[string]string{DisableEnv: "0"}, want: true},
		{env: map[string]string{DisableEnv: "off"}, want: true},
		{env: map[string]string{"CI": "true"}, want: true},
	} {
		if got := Disabled(func(k string) string { return tt.env[k] }); got != tt.want {
			t.Fatalf("Disabled(%v) = %v, want %v", tt.env, got, tt.want)
		}
	}
}
