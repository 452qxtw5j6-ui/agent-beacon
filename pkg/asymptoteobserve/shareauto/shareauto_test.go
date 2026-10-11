package shareauto

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	sub := filepath.Join(repo, "pkg", "x")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if d := Resolve(Settings{}, sub); d.Enabled || d.Source != "" {
		t.Fatalf("empty = %+v", d)
	}
	user := Settings{Auto: Auto{Enabled: true, Visibility: "private"}}
	if d := Resolve(user, sub); !d.Enabled || d.Visibility != "private" || d.Source != "user" {
		t.Fatalf("user = %+v", d)
	}
	// A marker turning it off wins on its own.
	if err := SaveMarker(repo, Marker{Auto: Auto{Enabled: false}}); err != nil {
		t.Fatal(err)
	}
	if d := Resolve(user, sub); d.Enabled || d.Source != "marker" || d.Project != repo {
		t.Fatalf("marker off = %+v", d)
	}
	// A marker asking for public auto-share does nothing without the user's trust.
	if err := SaveMarker(repo, Marker{Auto: Auto{Enabled: true, Visibility: "public"}}); err != nil {
		t.Fatal(err)
	}
	if d := Resolve(Settings{}, sub); d.Enabled || d.UntrustedMarker != repo {
		t.Fatalf("untrusted marker = %+v", d)
	}
	if d := Resolve(user, sub); d.Visibility != "private" || d.Source != "user" {
		t.Fatalf("untrusted marker overrode the user visibility: %+v", d)
	}
	// The user's project entry decides, with its own visibility.
	trusted := Settings{Projects: []Project{{Path: repo, Enabled: true, Visibility: "direct"}}}
	if d := Resolve(trusted, sub); !d.Enabled || d.Visibility != "direct" || d.Source != "project" {
		t.Fatalf("trusted = %+v", d)
	}
	optOut := Settings{Auto: Auto{Enabled: true}, Projects: []Project{{Path: repo, Enabled: false}}}
	if d := Resolve(optOut, sub); d.Enabled {
		t.Fatalf("project opt-out = %+v", d)
	}
	if d := Resolve(trusted, root); d.Enabled {
		t.Fatalf("outside the project = %+v", d)
	}
}

func TestForHookAndSave(t *testing.T) {
	path := filepath.Join(t.TempDir(), "endpoint", FileName)
	if d := ForHook(path, "/x"); d.Enabled {
		t.Fatal("missing file enabled")
	}
	if err := Save(path, Settings{Auto: Auto{Enabled: true, Visibility: "direct"}}); err != nil {
		t.Fatal(err)
	}
	if d := ForHook(path, "/x"); !d.Enabled || d.Visibility != "direct" {
		t.Fatalf("ForHook = %+v", d)
	}
	if info, err := os.Stat(path); err == nil && os.PathSeparator == '/' && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", info.Mode())
	}
	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := ForHook(path, "/x"); d.Enabled {
		t.Fatal("damaged file enabled")
	}
}

// Project entries match the directory however its path is spelled: through a symlink, with a
// trailing separator, or (on Windows) in another case or rooted on the current drive.
func TestResolveMatchesEquivalentPaths(t *testing.T) {
	real := t.TempDir()
	work := filepath.Join(real, "sub")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	s := Settings{Auto: Auto{Enabled: true}, Projects: []Project{{Path: real + string(filepath.Separator), Enabled: false}}}
	if d := Resolve(s, work); d.Enabled || d.Source != "project" {
		t.Fatalf("trailing separator: %+v", d)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err == nil {
		if d := Resolve(s, filepath.Join(link, "sub")); d.Enabled || d.Source != "project" {
			t.Fatalf("through a symlink: %+v", d)
		}
	}
	if runtime.GOOS == "windows" {
		if d := Resolve(s, strings.ToUpper(work)); d.Enabled || d.Source != "project" {
			t.Fatalf("other case: %+v", d)
		}
	}
	rootedOnly := Settings{Auto: Auto{Enabled: true}, Projects: []Project{{Path: "/work/project", Enabled: false}}}
	if d := Resolve(rootedOnly, "/work/project"); d.Enabled {
		t.Fatalf("rooted path: %+v", d)
	}
}
