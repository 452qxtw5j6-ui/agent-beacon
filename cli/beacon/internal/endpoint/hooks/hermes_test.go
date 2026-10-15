package hooks

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/testenv"
)

func TestInstallHermesConfigPreservesExistingSettingsAndHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	existing := `model: anthropic/claude-sonnet-4.6
hooks_auto_accept: true
hooks:
  pre_tool_call:
    - matcher: terminal
      command: ~/.hermes/agent-hooks/user-policy.sh
      timeout: 5
`
	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}

	if err := installHermesConfig(path, "/tmp/beacon hooks", "/tmp/runtime.jsonl", "/tmp/config.json"); err != nil {
		t.Fatalf("installHermesConfig returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(data)
	// The command now begins with a quote, so the YAML emitter single-quotes the whole scalar and
	// doubles the quotes inside it. The value a parser hands back is unchanged, which is what the hook
	// assertions below are about -- so they are made against that rather than against the on-disk
	// escaping. The preserved-settings assertions stay on the raw text, where the escaping is the point.
	parsed := strings.ReplaceAll(text, "''", "'")
	for _, want := range []string{
		"--log '/tmp/runtime.jsonl'",
		"--config '/tmp/config.json'",
		"'/tmp/beacon hooks' --platform hermes",
	} {
		if !strings.Contains(parsed, want) {
			t.Fatalf("Hermes hook command missing %q:\n%s", want, text)
		}
	}
	for _, want := range []string{
		"model:",
		"anthropic/claude-sonnet-4.6",
		"hooks_auto_accept: true",
		"~/.hermes/agent-hooks/user-policy.sh",
		"on_session_start:",
		"pre_llm_call:",
		"pre_tool_call:",
		"post_tool_call:",
		"pre_approval_request:",
		"post_approval_response:",
		"subagent_stop:",
		"on_session_end:",
		"on_session_finalize:",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("Hermes config missing %q:\n%s", want, text)
		}
	}
}

func TestInstallHermesConfigReplacesOnlyHermesBeaconHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	existing := `hooks:
  post_tool_call:
    - command: env BEACON_ENDPOINT_MODE=1 old-beacon-hooks --platform hermes post-tool
    - command: /tmp/asym-hooks --platform hermes post-tool
    - command: env BEACON_ENDPOINT_MODE=1 beacon-hooks --platform factory post-tool
    - command: echo keep
`
	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}

	if err := installHermesConfig(path, "/tmp/new-beacon-hooks", "/tmp/runtime.jsonl", "/tmp/config.json"); err != nil {
		t.Fatalf("installHermesConfig returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "old-beacon-hooks") || strings.Contains(text, "asym-hooks") {
		t.Fatalf("old Hermes endpoint hook was not replaced:\n%s", text)
	}
	for _, want := range []string{"--platform factory", "echo keep", "/tmp/new-beacon-hooks"} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected preserved hooks and new hook %q:\n%s", want, text)
		}
	}
}

func TestRemoveHermesEndpointHooksPreservesOtherHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	existing := `hooks:
  pre_tool_call:
    - matcher: terminal
      command: echo keep
    - command: env BEACON_ENDPOINT_MODE=1 beacon-hooks --platform hermes pre-tool
    - command: env BEACON_ENDPOINT_MODE=1 beacon-hooks --platform factory pre-tool
`
	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatal(err)
	}

	changed, err := removeHermesEndpointHooks(path)
	if err != nil {
		t.Fatalf("removeHermesEndpointHooks returned error: %v", err)
	}
	if !changed {
		t.Fatal("expected endpoint hook removal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "--platform hermes") {
		t.Fatalf("Hermes endpoint hook was not removed:\n%s", text)
	}
	if !strings.Contains(text, "echo keep") || !strings.Contains(text, "--platform factory") {
		t.Fatalf("non-Hermes hooks were not preserved:\n%s", text)
	}
}

// hermesTestHome moves the home directory to a temporary one, clears every variable that moves
// Hermes's home, and returns Hermes's native root there.
func hermesTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("HERMES_HOME", "")
	t.Setenv("HERMES_DATA_DIR_SUFFIX", "")
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "LocalAppData"))
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "LocalAppData", "hermes")
	}
	return filepath.Join(home, ".hermes")
}

func TestHermesHookStatusDetectsInstalled(t *testing.T) {
	native := hermesTestHome(t)
	path := filepath.Join(native, "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`hooks:
  on_session_end:
    - command: env BEACON_ENDPOINT_MODE=1 beacon-hooks --platform hermes session-end
`), 0600); err != nil {
		t.Fatal(err)
	}

	status := HermesHookStatus(HermesOptions{Level: LevelUser, UserMode: true})
	if !status.Installed {
		t.Fatalf("HermesHookStatus installed = false, status=%#v", status)
	}
	if status.ConfigPath != path {
		t.Fatalf("ConfigPath = %q, want %q", status.ConfigPath, path)
	}
}

func TestHermesProjectLevelReturnsClearError(t *testing.T) {
	if _, err := hermesConfigPath(LevelProject); err == nil || !strings.Contains(err.Error(), "user-level config only") {
		t.Fatalf("hermesConfigPath project err = %v, want user-level config only", err)
	}
}

// Install, status and uninstall resolve one config.yaml, the one Hermes reads: under HERMES_HOME
// when it is set, under the sticky profile when one is active, and ~/.hermes otherwise.
func TestHermesHooksInstallStatusUninstallAgreeOnHermesHome(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, native string) string
	}{
		{"unset", func(t *testing.T, native string) string { return native }},
		{"HERMES_HOME", func(t *testing.T, native string) string {
			dir := filepath.Join(t.TempDir(), "hermes-data")
			t.Setenv("HERMES_HOME", dir)
			return dir
		}},
		{"relative HERMES_HOME", func(t *testing.T, native string) string {
			t.Chdir(t.TempDir())
			cwd, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("HERMES_HOME", "relative-hermes")
			return filepath.Join(cwd, "relative-hermes")
		}},
		{"active profile", func(t *testing.T, native string) string {
			profile := filepath.Join(native, "profiles", "work")
			if err := os.MkdirAll(profile, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(native, "active_profile"), []byte("work\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return profile
		}},
		{"HERMES_HOME names a profile", func(t *testing.T, native string) string {
			profile := filepath.Join(t.TempDir(), "profiles", "coder")
			t.Setenv("HERMES_HOME", profile)
			return profile
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			native := hermesTestHome(t)
			want := filepath.Join(tc.setup(t, native), "config.yaml")
			opts := HermesOptions{Level: LevelUser, UserMode: true}

			installed, err := InstallHermes(opts)
			if err != nil {
				t.Fatalf("InstallHermes: %v", err)
			}
			if installed.ConfigPath != want {
				t.Fatalf("InstallHermes ConfigPath = %q, want %q", installed.ConfigPath, want)
			}
			if !isHermesInstalledAt(want) {
				t.Fatalf("no Beacon hooks in %s after install", want)
			}
			if want != filepath.Join(native, "config.yaml") {
				if _, err := os.Stat(filepath.Join(native, "config.yaml")); !os.IsNotExist(err) {
					t.Fatalf("InstallHermes also wrote the default config.yaml: %v", err)
				}
			}
			status := HermesHookStatus(opts)
			if !status.Installed || status.ConfigPath != want {
				t.Fatalf("HermesHookStatus = %#v, want installed at %q", status, want)
			}
			if !IsHermesInstalled(opts) {
				t.Fatal("IsHermesInstalled = false after install")
			}

			removed, err := UninstallHermes(opts)
			if err != nil {
				t.Fatalf("UninstallHermes: %v", err)
			}
			if removed.ConfigPath != want {
				t.Fatalf("UninstallHermes ConfigPath = %q, want %q", removed.ConfigPath, want)
			}
			if _, err := os.Stat(want); !os.IsNotExist(err) {
				t.Fatalf("config.yaml holding only Beacon hooks was not removed: %v", err)
			}
			if status := HermesHookStatus(opts); status.Installed || status.ConfigPath != want {
				t.Fatalf("HermesHookStatus after uninstall = %#v, want not installed at %q", status, want)
			}
		})
	}
}

// Hermes refuses to start when active_profile names a profile it cannot use, so hook install must
// fail rather than write the default profile's config.yaml.
func TestHermesHooksRefuseUnusableActiveProfile(t *testing.T) {
	native := hermesTestHome(t)
	if err := os.MkdirAll(native, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(native, "active_profile"), []byte("gone\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := HermesOptions{Level: LevelUser, UserMode: true}
	if _, err := InstallHermes(opts); err == nil || !strings.Contains(err.Error(), "active profile") {
		t.Fatalf("InstallHermes err = %v, want the active profile named", err)
	}
	for _, path := range []string{filepath.Join(native, "config.yaml"), filepath.Join(native, "profiles", "gone")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("InstallHermes created %s: %v", path, err)
		}
	}
	if status := HermesHookStatus(opts); status.Installed {
		t.Fatalf("HermesHookStatus = %#v, want not installed", status)
	}
}
