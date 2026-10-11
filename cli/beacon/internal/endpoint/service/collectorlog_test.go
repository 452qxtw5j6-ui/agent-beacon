package service

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/testenv"
)

// A failed install can only quote the collector's reason if it reads the file the backend actually
// sends stderr to -- the plist's StandardErrorPath and the supervised log -- or, where there is no
// file, tells the reader where to look.
func TestCollectorLogNamesWhereEachBackendSendsStderr(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)

	launchd := Manager{UserMode: true, Kind: KindLaunchd}.CollectorLog()
	if want := filepath.Join(home, "Library", "Logs", "Beacon", UserLabel+".err"); launchd.Path != want {
		t.Errorf("launchd user log = %q, want %q", launchd.Path, want)
	}
	stdout, stderr, err := launchdLogPaths(true, UserLabel)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plist(UserLabel, "/bin/otelcol", "/x/otelcol.yaml", stdout, stderr), "<string>"+launchd.Path+"</string>") {
		t.Errorf("launchd log path %q is not the plist's StandardErrorPath", launchd.Path)
	}
	if got := (Manager{UserMode: false, Kind: KindLaunchd}).CollectorLog().Path; got != "/Library/Logs/Beacon/"+SystemLabel+".err" {
		t.Errorf("launchd system log = %q, want /Library/Logs/Beacon/%s.err", got, SystemLabel)
	}

	supervised := Manager{UserMode: true, Kind: KindSupervised}.CollectorLog()
	if want := filepath.Join(home, ".beacon", "endpoint", "collector.out"); supervised.Path != want {
		t.Errorf("supervised log = %q, want %q", supervised.Path, want)
	}

	systemd := Manager{UserMode: true, Kind: KindSystemd}.CollectorLog()
	if systemd.Path != "" || !strings.Contains(systemd.Hint, "journalctl --user -u "+SystemdUserUnit) {
		t.Errorf("systemd user log = %+v, want a journalctl --user hint", systemd)
	}
	if hint := (Manager{UserMode: false, Kind: KindSystemd}).CollectorLog().Hint; strings.Contains(hint, "--user") || !strings.Contains(hint, SystemdSystemUnit) {
		t.Errorf("systemd system hint = %q", hint)
	}

	windows := Manager{UserMode: false, Kind: KindWindowsService}.CollectorLog()
	if windows.Path != "" || !strings.Contains(windows.Hint, WindowsServiceName) {
		t.Errorf("windows system log = %+v, want an event-log hint naming %s", windows, WindowsServiceName)
	}
}
