package environment

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func kinds(ws []Warning) map[string][]string {
	out := map[string][]string{}
	for _, w := range ws {
		out[w.Kind] = append(out[w.Kind], w.Subject)
	}
	return out
}

// The fixture reproduces what a manual audit found on a real machine: a native codex shadowed by
// an npm copy, a dangling backup link, a codex app-server under a nohup'd parent, a launchd job
// failing in a loop, and a plugin MCP server reached over SSH.
func TestScanReportsInstallsProcessesPluginsAndJobs(t *testing.T) {
	home := t.TempDir()
	prefix := filepath.Join(home, "brew")
	apps := filepath.Join(home, "Applications")
	localBin := filepath.Join(home, ".local", "bin")

	codexRelease := filepath.Join(home, ".codex", "packages", "standalone", "releases", "0.162.1-aarch64-apple-darwin")
	write(t, filepath.Join(codexRelease, "bin", "codex"), "bin")
	write(t, filepath.Join(home, ".codex", "packages", "standalone", "releases", "0.159.2-aarch64-apple-darwin", "bin", "codex"), "bin")
	symlink(t, filepath.Join(codexRelease, "bin", "codex"), filepath.Join(localBin, "codex"))
	symlink(t, "/Applications/Codex.app/Contents/Resources/codex", filepath.Join(localBin, "codex.dangling-backup"))

	claudeVersion := filepath.Join(home, ".local", "share", "claude", "versions", "2.1.300")
	write(t, claudeVersion, "bin")
	symlink(t, claudeVersion, filepath.Join(localBin, "claude"))

	write(t, filepath.Join(prefix, "lib", "node_modules", "@openai", "codex", "package.json"), `{"version":"0.159.2"}`)
	write(t, filepath.Join(prefix, "lib", "node_modules", "@openai", "codex", "bin", "codex.js"), "js")
	symlink(t, filepath.Join(prefix, "lib", "node_modules", "@openai", "codex", "bin", "codex.js"), filepath.Join(prefix, "bin", "codex"))
	write(t, filepath.Join(apps, "ChatGPT.app", "Contents", "Resources", "codex-cli", "codex-package.json"), `{"version":"0.162.0-alpha.17.2"}`)

	write(t, filepath.Join(home, ".claude", "plugins", "installed_plugins.json"), `{"version":2,"plugins":{
		"data-hub@mine":[{"scope":"user","installPath":"`+filepath.Join(home, "plug", "data-hub")+`","version":"0.5"}],
		"off@mine":[{"scope":"user","installPath":"`+filepath.Join(home, "plug", "off")+`","version":"1"}]}}`)
	write(t, filepath.Join(home, "plug", "data-hub", ".mcp.json"), `{"mcpServers":{
		"redash":{"type":"http","url":"https://example.invalid/mcp"},
		"dbt":{"command":"bash","args":["${CLAUDE_PLUGIN_ROOT}/scripts/remote.sh"]}}}`)
	write(t, filepath.Join(home, "plug", "data-hub", "scripts", "remote.sh"), "#!/bin/bash\nexec ssh -o BatchMode=yes host entry mcp\n")
	write(t, filepath.Join(home, "plug", "off", ".mcp.json"), `{"x":{"command":"ssh","args":["host"]}}`)
	write(t, filepath.Join(home, ".claude", "settings.json"), `{"enabledPlugins":{"off@mine":false}}`)
	write(t, filepath.Join(home, ".codex", "config.toml"), "[plugins.\"github@openai-curated\"]\nenabled = true\n[plugins.\"slack@openai-curated\"]\nenabled = false\n")

	write(t, filepath.Join(home, "Library", "LaunchAgents", "com.test.remote.plist"), "plist")
	write(t, filepath.Join(home, "Library", "LaunchAgents", "com.test.tunnel.plist"), "plist")
	write(t, filepath.Join(home, "Library", "LaunchAgents", "com.test.other.plist"), "plist")
	errLog := filepath.Join(home, "remote.err.log")
	write(t, errLog, strings.Repeat("Error: connection is errored\n", 6))

	codexExe := filepath.Join(codexRelease, "bin", "codex")
	run := func(name string, args ...string) ([]byte, error) {
		switch {
		case name == "ps" && strings.Contains(strings.Join(args, " "), "comm="):
			return []byte(strings.Join([]string{
				"  100     1   1-02:03:04  4096 /usr/local/bin/tunnel-client",
				"  101   100   1-02:03:04  33792 " + codexExe,
				"  200     1      10:00   2048 /usr/local/bin/tunnel-client",
				"  201   200      10:00   2048 " + codexExe,
				"  300     1  20-00:00:00  1024 /gone/codex-old/bin/codex",
				"  400     1      05:00   1024 /Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper",
			}, "\n")), nil
		case name == "ps":
			return []byte("  101 codex app-server --token=s3cret\n  201 " + codexExe + " app-server\n  300 codex --flag\n"), nil
		case name == "launchctl":
			return []byte("PID\tStatus\tLabel\n200\t0\tcom.test.tunnel\n-\t1\tcom.test.remote\n-\t0\tcom.test.other\n"), nil
		case name == "plutil":
			switch filepath.Base(args[len(args)-1]) {
			case "com.test.remote.plist":
				return []byte(`{"Label":"com.test.remote","ProgramArguments":["/home/bin/ensure-codex-remote-control"],"StartInterval":300,"RunAtLoad":true,"StandardErrorPath":"` + errLog + `"}`), nil
			case "com.test.tunnel.plist":
				return []byte(`{"Label":"com.test.tunnel","ProgramArguments":["/usr/local/bin/tunnel-client","run","--key=abc"],"KeepAlive":true}`), nil
			default:
				return []byte(`{"Label":"com.test.other","ProgramArguments":["/bin/true"]}`), nil
			}
		}
		return nil, errors.New("unexpected command")
	}

	report := Scan(Options{
		HomeDir:    home,
		AppsDir:    apps,
		BinDirs:    []string{localBin, filepath.Join(prefix, "bin")},
		PrefixDirs: []string{prefix},
		Now:        func() time.Time { return time.Now() },
		Run:        run,
	})

	var activeCodex *Install
	for i, item := range report.Installs {
		if item.Tool == ToolCodex && item.Kind == KindEntrypoint && item.Active {
			activeCodex = &report.Installs[i]
		}
	}
	if activeCodex == nil || activeCodex.Source != SourceNative || activeCodex.Version != "0.162.1" {
		t.Fatalf("active codex entrypoint = %+v", activeCodex)
	}
	activeVersions := 0
	for _, item := range report.Installs {
		if item.Tool == ToolCodex && item.Kind == KindVersion && item.Active {
			activeVersions++
			if item.Version != "0.162.1" {
				t.Fatalf("active version = %s", item.Version)
			}
		}
	}
	if activeVersions != 1 {
		t.Fatalf("active codex versions = %d", activeVersions)
	}

	got := kinds(report.Warnings)
	if strings.Join(got["duplicate_install"], ",") != "codex" {
		t.Fatalf("duplicate_install = %v", got["duplicate_install"])
	}
	if len(got["broken_link"]) != 1 || !strings.HasSuffix(got["broken_link"][0], "codex.dangling-backup") {
		t.Fatalf("broken_link = %v", got["broken_link"])
	}
	unmanaged := strings.Join(got["unmanaged_process"], ",")
	if !strings.Contains(unmanaged, "101 codex app-server") || strings.Contains(unmanaged, "201") {
		t.Fatalf("unmanaged_process = %v", got["unmanaged_process"])
	}
	if !strings.Contains(strings.Join(got["long_running"], ","), "300") || !strings.Contains(strings.Join(got["deleted_executable"], ","), "300") {
		t.Fatalf("long_running/deleted = %v / %v", got["long_running"], got["deleted_executable"])
	}
	if strings.Join(got["ssh_mcp"], ",") != "data-hub/dbt" {
		t.Fatalf("ssh_mcp = %v", got["ssh_mcp"])
	}
	if strings.Join(got["job_failing"], ",") != "com.test.remote" || strings.Join(got["job_errors"], ",") != "com.test.remote" {
		t.Fatalf("job warnings = %v / %v", got["job_failing"], got["job_errors"])
	}

	for _, proc := range report.Processes {
		if strings.Contains(proc.Executable, "Frameworks") {
			t.Fatalf("app helper reported as a tool process: %+v", proc)
		}
		if proc.PID == 101 && proc.Subcommand != "app-server" {
			t.Fatalf("subcommand = %q", proc.Subcommand)
		}
		if proc.PID == 201 && (proc.SupervisorKind != SupervisorLaunchd || proc.Supervisor != "com.test.tunnel") {
			t.Fatalf("supervisor = %+v", proc)
		}
		if proc.PID == 300 && proc.Subcommand != "" {
			t.Fatalf("flag kept as subcommand: %q", proc.Subcommand)
		}
	}

	labels := map[string]LaunchJob{}
	for _, job := range report.LaunchJobs {
		labels[job.Label] = job
	}
	if _, ok := labels["com.test.other"]; ok {
		t.Fatal("unrelated launch job reported")
	}
	if job := labels["com.test.tunnel"]; !job.Running || strings.Join(job.Tools, ",") != "codex" {
		t.Fatalf("tunnel job = %+v", job)
	}

	plugins := map[string]Plugin{}
	for _, plugin := range report.Plugins {
		plugins[plugin.Runtime+"/"+plugin.Name] = plugin
	}
	if p := plugins["claude_code/off"]; p.Enabled {
		t.Fatalf("disabled plugin reported enabled: %+v", p)
	}
	if p := plugins["codex_cli/slack"]; p.Enabled || !plugins["codex_cli/github"].Enabled {
		t.Fatalf("codex plugins = %+v", report.Plugins)
	}
}

// Nothing that could carry a secret survives: no argument beyond a bare subcommand word.
func TestReportNeverRetainsArguments(t *testing.T) {
	for _, tc := range []struct{ exe, args, want string }{
		{"/x/codex", "/x/codex app-server --token=abc", "app-server"},
		{"/x/codex", "codex --api-key sk-123", ""},
		{"/x/codex", "/x/codex sk-live-ABCDEF", ""},
		{"/x/claude", "/x/claude --print hello", ""},
		{"/x/claude", "claude rc --name submac", "rc"},
	} {
		if got := subcommand(tc.exe, tc.args); got != tc.want {
			t.Fatalf("subcommand(%q) = %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestParseEtime(t *testing.T) {
	for in, want := range map[string]int64{"05": 5, "01:05": 65, "02:01:05": 7265, "3-00:00:01": 259201} {
		if got := parseEtime(in); got != want {
			t.Fatalf("parseEtime(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestReportsArePublishedAndFetched(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	fresh := Report{Host: "server", GeneratedAt: now.Add(-5 * time.Minute).Format(time.RFC3339), Warnings: []Warning{{Kind: "duplicate_install", Subject: "codex"}}}
	old := Report{Host: "laptop", GeneratedAt: now.Add(-2 * time.Hour).Format(time.RFC3339)}
	for name, report := range map[string]Report{"server.json": fresh, "laptop.json": old} {
		if err := WriteFile(filepath.Join(dir, name), report); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(dir, "broken.json"), "{not json")
	if leftovers, _ := filepath.Glob(filepath.Join(dir, ".environment-*")); len(leftovers) != 0 {
		t.Fatalf("temporary files left behind: %v", leftovers)
	}
	server := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer server.Close()
	got := FetchReports(server.Client(), []string{server.URL + "/server.json", server.URL + "/laptop.json", server.URL + "/broken.json", server.URL + "/missing.json"}, now)
	if len(got) != 4 {
		t.Fatalf("FetchReports = %+v", got)
	}
	if got[0].Host != "server" || got[0].Stale || got[0].Error != "" || len(got[0].Warnings) != 1 {
		t.Fatalf("fresh report = %+v", got[0])
	}
	if got[1].Host != "laptop" || !got[1].Stale {
		t.Fatalf("old report = %+v", got[1])
	}
	for _, item := range got[2:] {
		if item.Error == "" || !item.Stale || item.Source == "" {
			t.Fatalf("unreadable report = %+v", item)
		}
	}
	if FetchReports(server.Client(), nil, now) != nil {
		t.Fatal("no addresses must fetch nothing")
	}
}
