// Package shareauto holds the auto-share setting: whether the hook adapter records one
// session.share_requested event per session, which Beacon Cloud forwarding ships to beacon.sh and
// beacon.sh turns into a shared trace that it keeps refreshing as more of the session arrives.
//
// The hooks never publish anything themselves and never touch the network: they only write that
// local event, and only when the person turned the setting on with `beacon share auto enable`.
//
// Two files hold the setting:
//
//   - The user file, ~/.beacon/endpoint/share.json (0600 under 0700), written only by the CLI. It
//     has the user-wide switch and the projects the user opted in or out of, by absolute path.
//   - A project marker, <project>/.beacon/share.json, which `--project` writes so a repository can
//     record its choice. A marker can turn auto-share off for its project on its own. It can turn it
//     on only for someone whose user file trusts that project: a marker arrives with a clone, and a
//     repository must never be able to publish the sessions of whoever opens it. The visibility of
//     a trusted project always comes from the user file, never from the marker.
package shareauto

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const (
	// FileName is the user file's name under the endpoint base directory, and the marker's name
	// under a project's .beacon directory.
	FileName = "share.json"
	// MarkerDir is the project directory that holds the marker.
	MarkerDir = ".beacon"
	// PathEnv overrides where the user file lives (tests, unusual homes).
	PathEnv = "BEACON_SHARE_SETTINGS_FILE"
	// SchemaVersion is written into both files.
	SchemaVersion = "beacon.share_settings.v1"

	// ActionShareRequested is the event the hook adapter writes once per session when auto-share
	// applies to it.
	ActionShareRequested = "session.share_requested"

	// maxWalk bounds how many directories are searched above a working directory for a project.
	maxWalk = 64
)

// Auto is one auto-share switch and the visibility it shares with ("" means the server default,
// direct).
type Auto struct {
	Enabled    bool   `json:"enabled"`
	Visibility string `json:"visibility,omitempty"`
}

// Project is the user's choice for one project directory.
type Project struct {
	Path       string `json:"path"`
	Enabled    bool   `json:"enabled"`
	Visibility string `json:"visibility,omitempty"`
}

// Settings is the user file.
type Settings struct {
	SchemaVersion string    `json:"schema_version"`
	Auto          Auto      `json:"auto"`
	Projects      []Project `json:"projects,omitempty"`
}

// Marker is a project's .beacon/share.json.
type Marker struct {
	SchemaVersion string `json:"schema_version"`
	Auto          Auto   `json:"auto"`
}

// Decision is what applies to one working directory.
type Decision struct {
	Enabled    bool
	Visibility string
	// Source is "user", "project" (the user's entry for a project), "marker" (a project marker
	// turned it off) or "" when nothing is configured.
	Source string
	// Project is the project directory the decision came from, when it came from one.
	Project string
	// UntrustedMarker is a marker that asks for auto-share in a project the user has not opted in.
	UntrustedMarker string
}

// DefaultPath is BEACON_SHARE_SETTINGS_FILE, or ~/.beacon/endpoint/share.json.
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

// MarkerPath is dir's project marker.
func MarkerPath(dir string) string { return filepath.Join(dir, MarkerDir, FileName) }

// Load reads the user file. A missing file is an empty Settings and no error.
func Load(path string) (Settings, error) {
	s := Settings{SchemaVersion: SchemaVersion}
	if path == "" {
		return s, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return s, err
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{SchemaVersion: SchemaVersion}, err
	}
	s.SchemaVersion = SchemaVersion
	return s, nil
}

// LoadMarker reads dir's project marker; ok is false when there is none or it cannot be read.
func LoadMarker(dir string) (Marker, bool) {
	data, err := os.ReadFile(MarkerPath(dir))
	if err != nil {
		return Marker{}, false
	}
	var m Marker
	if err := json.Unmarshal(data, &m); err != nil {
		return Marker{}, false
	}
	return m, true
}

// anyEnabled reports whether anything in s could turn auto-share on, so the hook path can skip
// the directory walk entirely when the feature is not in use.
func (s Settings) anyEnabled() bool {
	if s.Auto.Enabled {
		return true
	}
	for _, p := range s.Projects {
		if p.Enabled {
			return true
		}
	}
	return false
}

// Project returns the user's entry for dir.
func (s Settings) Project(dir string) (Project, bool) {
	dir = filepath.Clean(dir)
	for _, p := range s.Projects {
		if filepath.Clean(p.Path) == dir {
			return p, true
		}
	}
	return Project{}, false
}

// Resolve decides whether auto-share applies in workDir. The nearest enclosing directory that has
// a user entry or a marker decides; a marker that asks for auto-share without a user entry is
// reported and otherwise ignored. With neither, the user-wide switch decides.
func Resolve(s Settings, workDir string) Decision {
	var d Decision
	dir := filepath.Clean(workDir)
	if workDir != "" && filepath.IsAbs(dir) {
		for i := 0; i < maxWalk; i++ {
			if p, ok := s.Project(dir); ok {
				return Decision{Enabled: p.Enabled, Visibility: p.Visibility, Source: "project", Project: dir}
			}
			if m, ok := LoadMarker(dir); ok {
				if !m.Auto.Enabled {
					return Decision{Source: "marker", Project: dir}
				}
				if d.UntrustedMarker == "" {
					d.UntrustedMarker = dir
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	if s.Auto.Enabled {
		d.Enabled, d.Visibility, d.Source = true, s.Auto.Visibility, "user"
	}
	return d
}

// ForHook is Resolve for the hook path: it reads the user file and returns a disabled decision at
// the cost of one failed read when nothing could enable auto-share.
func ForHook(path, workDir string) Decision {
	s, err := Load(path)
	if err != nil || !s.anyEnabled() {
		return Decision{}
	}
	return Resolve(s, workDir)
}

// Save writes the user file atomically, 0600 under a 0700 directory.
func Save(path string, s Settings) error {
	s.SchemaVersion = SchemaVersion
	return writeJSON(path, s, 0o700, 0o600)
}

// SaveMarker writes dir's project marker. It is meant to be committed, so it is an ordinary file.
func SaveMarker(dir string, m Marker) error {
	m.SchemaVersion = SchemaVersion
	return writeJSON(MarkerPath(dir), m, 0o755, 0o644)
}

func writeJSON(path string, v any, dirMode, fileMode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+FileName+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(fileMode); err != nil {
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
	return os.Rename(name, path)
}
