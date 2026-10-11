package cmd

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/managedprivacy"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve/shareauto"
)

func runShareAuto(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	shareAutoOpts = shareAutoOptions{}
	for _, c := range []*pflag.FlagSet{shareAutoEnableCmd.Flags(), shareAutoDisableCmd.Flags(), shareAutoStatusCmd.Flags()} {
		c.VisitAll(func(f *pflag.Flag) { _ = f.Value.Set(f.DefValue); f.Changed = false })
	}
	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs(append([]string{"share", "auto"}, args...))
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	err := rootCmd.Execute()
	return stdout.String(), stderr.String(), err
}

func shareAutoTestEnv(t *testing.T, connected bool, mode string) string {
	t.Helper()
	env := newShareEnv(t)
	path := filepath.Join(env.home, ".beacon", "endpoint", shareauto.FileName)
	t.Setenv(shareauto.PathEnv, path)
	prev := shareAutoCloud
	shareAutoCloud = func() (bool, string) { return connected, mode }
	t.Cleanup(func() { shareAutoCloud = prev })
	return path
}

func TestShareAutoEnableAndDisable(t *testing.T) {
	path := shareAutoTestEnv(t, true, managedprivacy.Standard)
	stdout, stderr, err := runShareAuto(t, "enable", "--visibility", "private")
	if err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !strings.Contains(stdout, "Auto-share is on for every new session (private)") || stderr != "" {
		t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
	}
	settings, _ := shareauto.Load(path)
	if !settings.Auto.Enabled || settings.Auto.Visibility != "private" {
		t.Fatalf("settings = %+v", settings)
	}
	if _, _, err := runShareAuto(t, "disable"); err != nil {
		t.Fatalf("disable: %v", err)
	}
	settings, _ = shareauto.Load(path)
	if settings.Auto.Enabled {
		t.Fatalf("still enabled: %+v", settings)
	}
}

func TestShareAutoWarnsWithoutCloudOrContent(t *testing.T) {
	shareAutoTestEnv(t, false, "")
	_, stderr, err := runShareAuto(t, "enable")
	if err != nil || !strings.Contains(stderr, "not connected to Beacon Cloud") {
		t.Fatalf("not connected: err=%v stderr=%q", err, stderr)
	}
	shareAutoTestEnv(t, true, managedprivacy.MetadataOnly)
	_, stderr, err = runShareAuto(t, "enable")
	if err != nil || !strings.Contains(stderr, "metadata-only") {
		t.Fatalf("metadata-only: err=%v stderr=%q", err, stderr)
	}
}

func TestShareAutoPublicNeedsYesWithoutATerminal(t *testing.T) {
	path := shareAutoTestEnv(t, true, managedprivacy.Standard)
	if _, _, err := runShareAuto(t, "enable", "--visibility", "public"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("public without --yes: %v", err)
	}
	if settings, _ := shareauto.Load(path); settings.Auto.Enabled {
		t.Fatal("refused public enable still wrote the setting")
	}
	if _, _, err := runShareAuto(t, "enable", "--visibility", "public", "--yes"); err != nil {
		t.Fatalf("public --yes: %v", err)
	}
	if _, _, err := runShareAuto(t, "enable", "--visibility", "everyone"); err == nil {
		t.Fatal("bad visibility accepted")
	}
}

func TestShareAutoProjectScopeAndStatus(t *testing.T) {
	path := shareAutoTestEnv(t, true, managedprivacy.Standard)
	project := t.TempDir()
	if _, _, err := runShareAuto(t, "enable", "--project", project); err != nil {
		t.Fatalf("enable --project: %v", err)
	}
	settings, _ := shareauto.Load(path)
	if entry, ok := settings.Project(project); !ok || !entry.Enabled || entry.Visibility != "direct" || settings.Auto.Enabled {
		t.Fatalf("settings = %+v", settings)
	}
	if marker, ok := shareauto.LoadMarker(project); !ok || !marker.Auto.Enabled {
		t.Fatalf("marker = %+v %v", marker, ok)
	}
	stdout, _, err := runShareAuto(t, "status", "--project", filepath.Join(project), "--json")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var doc struct {
		OK   bool            `json:"ok"`
		Data shareAutoStatus `json:"data"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil || !doc.Data.Enabled || doc.Data.Source != "project" || !doc.Data.CloudConnected {
		t.Fatalf("status = %s (%v)", stdout, err)
	}

	// Someone else's clone: the marker alone does not enable anything, and status says why.
	other := t.TempDir()
	if err := shareauto.SaveMarker(other, shareauto.Marker{Auto: shareauto.Auto{Enabled: true, Visibility: "public"}}); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = runShareAuto(t, "status", "--project", other)
	if err != nil || !strings.Contains(stdout, "Auto-share in "+other+": off") || !strings.Contains(stdout, "applies only after you run") {
		t.Fatalf("untrusted status = %q (%v)", stdout, err)
	}

	if _, _, err := runShareAuto(t, "disable", "--project", project); err != nil {
		t.Fatalf("disable --project: %v", err)
	}
	settings, _ = shareauto.Load(path)
	if entry, _ := settings.Project(project); entry.Enabled {
		t.Fatalf("project still enabled: %+v", settings)
	}
	if marker, _ := shareauto.LoadMarker(project); marker.Auto.Enabled {
		t.Fatal("marker still enabled")
	}
}

// A user-wide disable turns off projects enabled with --project too: their entries are checked
// before the user-wide switch, so leaving one on would keep publishing after "off for every new
// session".
func TestShareAutoGlobalDisableTurnsOffProjects(t *testing.T) {
	path := shareAutoTestEnv(t, true, managedprivacy.Standard)
	project := t.TempDir()
	if _, _, err := runShareAuto(t, "enable", "--project", project); err != nil {
		t.Fatalf("enable --project: %v", err)
	}
	if !shareauto.ForHook(path, project).Enabled {
		t.Fatal("the project is not enabled")
	}
	stdout, _, err := runShareAuto(t, "disable")
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if !strings.Contains(stdout, "Auto-share is off for every new session") || !strings.Contains(stdout, "Turned off for the project "+project) {
		t.Fatalf("stdout = %q", stdout)
	}
	settings, _ := shareauto.Load(path)
	if entry, ok := settings.Project(project); !ok || entry.Enabled {
		t.Fatalf("project entry = %+v %v, want kept and off", entry, ok)
	}
	// What the hook adapter decides: no session.share_requested is written in the project.
	if d := shareauto.ForHook(path, filepath.Join(project, "sub")); d.Enabled {
		t.Fatalf("hook decision after a global disable = %+v", d)
	}
	stdout, _, err = runShareAuto(t, "status", "--project", project)
	if err != nil || !strings.Contains(stdout, "Auto-share in "+project+": off") {
		t.Fatalf("status = %q (%v)", stdout, err)
	}
}
