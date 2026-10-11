package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/selfupdate"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/updatecheck"
)

func TestPrintRootSplash(t *testing.T) {
	cmd := &cobra.Command{Use: "beacon"}
	var out bytes.Buffer
	cmd.SetOut(&out)

	printRootSplash(cmd)

	got := out.String()
	for _, want := range []string{
		"██████╗ ███████╗ █████╗  ██████╗ ██████╗ ███╗   ██╗",
		"Open-source telemetry layer for AI agents.",
		"Start with:",
		"beacon endpoint install",
		"beacon endpoint status",
		"beacon endpoint wazuh print-config",
		"Usage:",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("root splash missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b[") {
		t.Fatalf("root splash written to a buffer should not include ANSI escapes:\n%q", got)
	}
	for _, line := range beaconBanner {
		if len([]rune(line)) > 64 {
			t.Fatalf("banner line %q is too wide: got %d columns", line, len(line))
		}
	}
}

func TestPrintRootUpdateNotice(t *testing.T) {
	result := updatecheck.Result{
		CurrentVersion:  "v1.3.33",
		LatestVersion:   "v1.3.34",
		UpdateAvailable: true,
	}

	tests := []struct {
		name    string
		install selfupdate.Install
		command string
	}{
		{name: "homebrew", install: selfupdate.Install{Kind: selfupdate.InstallHomebrew}, command: "brew upgrade beacon"},
		{name: "system package", install: selfupdate.Install{Kind: selfupdate.InstallSystemPkg}, command: "sudo beacon endpoint update --apply"},
		{name: "other", install: selfupdate.Install{Kind: selfupdate.InstallOther}, command: "beacon endpoint update"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			printRootUpdateNotice(&out, result, false, tt.install)
			got := out.String()
			for _, want := range []string{
				"Update available · v1.3.33 → v1.3.34",
				"Release notes: https://docs.beacon.sh/changelog/cli",
				"Update with: " + tt.command,
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("update notice missing %q:\n%s", want, got)
				}
			}
			if strings.Contains(got, "\x1b[") {
				t.Fatalf("uncolored update notice includes ANSI escapes: %q", got)
			}
		})
	}
}

func TestPrintRootUpdateNoticeUsesOrange(t *testing.T) {
	var out bytes.Buffer
	printRootUpdateNotice(&out, updatecheck.Result{
		CurrentVersion:  "v1.3.33",
		LatestVersion:   "v1.3.34",
		UpdateAvailable: true,
	}, true, selfupdate.Install{Kind: selfupdate.InstallHomebrew})

	if !strings.HasPrefix(out.String(), beaconOrange) {
		t.Fatalf("colored update notice does not start orange: %q", out.String())
	}
	if !strings.Contains(out.String(), resetColor) {
		t.Fatalf("colored update notice does not reset color: %q", out.String())
	}
}

func TestRootUpdateNoticeSkipsNonInteractiveCommands(t *testing.T) {
	oldChecker := newRootVersionChecker
	t.Cleanup(func() { newRootVersionChecker = oldChecker })
	called := false
	newRootVersionChecker = func(string) versionChecker {
		called = true
		return stubVersionChecker{}
	}

	cmd := &cobra.Command{}
	cmd.SetIn(bytes.NewBuffer(nil))
	cmd.SetOut(&bytes.Buffer{})
	maybePrintRootUpdateNotice(cmd)
	if called {
		t.Fatal("non-interactive root command performed an update check")
	}
}

// isTerminal gates the full-screen onboarding wizard and the trace browser, so
// anything that is not a real terminal has to read as false.
//
// This previously tested os.ModeCharDevice, which /dev/null also sets. The result
// was that `beacon endpoint install < /dev/null` -- an ordinary shape for a wrapper
// script or an unattended run -- looked interactive, started the wizard against an
// input already at EOF, and failed the install with "onboarding cancelled".
func TestIsTerminalRejectsDevNullPipesAndRegularFiles(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()

	regular, err := os.Create(filepath.Join(t.TempDir(), "redirected.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()

	for name, file := range map[string]*os.File{
		"/dev/null":    devNull,
		"pipe read":    readEnd,
		"pipe write":   writeEnd,
		"regular file": regular,
		"nil":          nil,
	} {
		if isTerminal(file) {
			t.Fatalf("isTerminal(%s) = true, want false", name)
		}
	}
}
