// Package environment reports how the Claude Code and Codex CLIs are installed and running on
// this machine: every install of each CLI, the processes they run and what supervises them, the
// plugins that add MCP servers to them, and the launchd jobs that start them.
//
// It is a read-only, on-demand scan. It never executes the CLIs it finds, never retains command
// arguments or environment values (only executable paths and a bare subcommand word), and reads
// log files only to count error lines. It is not part of the scheduled inventory snapshot.
package environment

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
)

const (
	ToolClaude = "claude"
	ToolCodex  = "codex"

	SourceNative   = "native"
	SourceNPM      = "npm"
	SourceHomebrew = "homebrew"
	SourceApp      = "app"
	SourceUnknown  = "unknown"

	KindEntrypoint = "entrypoint"
	KindVersion    = "version"
	KindPackage    = "package"
	KindCask       = "homebrew"
	KindAppBundle  = "app_bundle"

	SupervisorLaunchd   = "launchd"
	SupervisorApp       = "app"
	SupervisorUnmanaged = "unmanaged"

	DefaultStaleAfter = 7 * 24 * time.Hour
)

var tools = []string{ToolClaude, ToolCodex}

type Options struct {
	HomeDir string
	// AppsDir is where application bundles live; defaults to /Applications.
	AppsDir string
	// BinDirs overrides the directories searched for CLI entrypoints, in PATH order.
	BinDirs []string
	// PrefixDirs overrides the package-manager prefixes (Homebrew, npm) that are searched.
	PrefixDirs []string
	Now        func() time.Time
	// Run executes a read-only system command (ps, launchctl, plutil). Tests replace it.
	Run        func(name string, args ...string) ([]byte, error)
	StaleAfter time.Duration
}

type Report struct {
	GeneratedAt string      `json:"generated_at"`
	Host        string      `json:"host"`
	Supported   bool        `json:"supported"`
	Installs    []Install   `json:"installs"`
	Processes   []Process   `json:"processes"`
	Plugins     []Plugin    `json:"plugins"`
	LaunchJobs  []LaunchJob `json:"launch_jobs"`
	Warnings    []Warning   `json:"warnings"`
}

type Install struct {
	Tool    string `json:"tool"`
	Kind    string `json:"kind"`
	Source  string `json:"source"`
	Path    string `json:"path"`
	Target  string `json:"target,omitempty"`
	Version string `json:"version,omitempty"`
	// Active marks the entrypoint a shell resolves first, and the version it points to.
	Active bool `json:"active"`
	Broken bool `json:"broken,omitempty"`
}

type Process struct {
	PID               int    `json:"pid"`
	PPID              int    `json:"ppid"`
	Tool              string `json:"tool"`
	Executable        string `json:"executable"`
	Subcommand        string `json:"subcommand,omitempty"`
	Uptime            string `json:"uptime"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
	RSSMB             int    `json:"rss_mb"`
	Supervisor        string `json:"supervisor"`
	SupervisorKind    string `json:"supervisor_kind"`
	ExecutableMissing bool   `json:"executable_missing,omitempty"`
}

type Plugin struct {
	Runtime     string      `json:"runtime"`
	Name        string      `json:"name"`
	Marketplace string      `json:"marketplace,omitempty"`
	Version     string      `json:"version,omitempty"`
	Scope       string      `json:"scope,omitempty"`
	Enabled     bool        `json:"enabled"`
	MCPServers  []PluginMCP `json:"mcp_servers,omitempty"`
}

type PluginMCP struct {
	Name      string `json:"name"`
	Transport string `json:"transport"`
	Command   string `json:"command,omitempty"`
	ViaSSH    bool   `json:"via_ssh,omitempty"`
}

type LaunchJob struct {
	Label         string   `json:"label"`
	Path          string   `json:"path"`
	Program       string   `json:"program,omitempty"`
	Tools         []string `json:"tools,omitempty"`
	Running       bool     `json:"running"`
	PID           int      `json:"pid,omitempty"`
	LastExit      *int     `json:"last_exit,omitempty"`
	StartInterval int      `json:"start_interval,omitempty"`
	KeepAlive     bool     `json:"keep_alive,omitempty"`
	RecentErrors  int      `json:"recent_errors,omitempty"`
}

type Warning struct {
	Kind    string `json:"kind"`
	Subject string `json:"subject"`
	Message string `json:"message"`
}

func Scan(opts Options) Report {
	opts = withDefaults(opts)
	host, _ := os.Hostname()
	report := Report{
		GeneratedAt: opts.Now().UTC().Format(time.RFC3339),
		Host:        host,
		Supported:   runtime.GOOS == "darwin",
	}
	report.Installs = scanInstalls(opts)
	labels := launchdLabels(opts)
	report.Processes = scanProcesses(opts, labels)
	report.Plugins = scanPlugins(opts)
	report.LaunchJobs = scanLaunchJobs(opts, labels, report.Processes)
	report.Warnings = warnings(opts, report)
	return report
}

func withDefaults(opts Options) Options {
	if opts.HomeDir == "" {
		opts.HomeDir, _ = os.UserHomeDir()
	}
	if opts.AppsDir == "" {
		opts.AppsDir = "/Applications"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Run == nil {
		opts.Run = func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).Output()
		}
	}
	if opts.StaleAfter == 0 {
		opts.StaleAfter = DefaultStaleAfter
	}
	if opts.PrefixDirs == nil {
		opts.PrefixDirs = []string{"/opt/homebrew", "/usr/local", filepath.Join(opts.HomeDir, ".local"), filepath.Join(opts.HomeDir, ".npm-global")}
	}
	if opts.BinDirs == nil {
		dirs := filepath.SplitList(os.Getenv("PATH"))
		// A launchd job has a minimal PATH, so append where shells usually find these CLIs.
		dirs = append(dirs, filepath.Join(opts.HomeDir, ".local", "bin"), filepath.Join(opts.HomeDir, ".bun", "bin"))
		for _, prefix := range opts.PrefixDirs {
			dirs = append(dirs, filepath.Join(prefix, "bin"))
		}
		opts.BinDirs = uniqueStrings(dirs)
	}
	return opts
}

// --- installs ---

func scanInstalls(opts Options) []Install {
	var out []Install
	for _, tool := range tools {
		entrypoints := scanEntrypoints(opts, tool)
		activeTarget := ""
		for _, item := range entrypoints {
			if item.Active {
				activeTarget = item.Target
			}
		}
		out = append(out, entrypoints...)
		out = append(out, scanVersions(opts, tool, activeTarget)...)
		out = append(out, scanPackages(opts, tool)...)
		out = append(out, scanAppBundles(opts, tool)...)
	}
	return out
}

func scanEntrypoints(opts Options, tool string) []Install {
	var out []Install
	activeFound := false
	for _, dir := range opts.BinDirs {
		names := []string{tool}
		// Renamed leftovers such as codex.homebrew-0.121.0.backup are reported only when broken.
		matches, _ := filepath.Glob(filepath.Join(dir, tool+".*"))
		for _, match := range matches {
			names = append(names, filepath.Base(match))
		}
		for _, name := range names {
			path := filepath.Join(dir, name)
			info, err := os.Lstat(path)
			if err != nil {
				continue
			}
			item := Install{Tool: tool, Kind: KindEntrypoint, Path: path}
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := filepath.EvalSymlinks(path)
				if err != nil {
					item.Broken = true
					item.Target, _ = os.Readlink(path)
				} else {
					item.Target = target
				}
			} else {
				item.Target = path
			}
			if name != tool && !item.Broken {
				continue
			}
			item.Source = classifySource(item.Target)
			item.Version = versionFromPath(item.Target)
			if name == tool && !item.Broken && !activeFound {
				item.Active = true
				activeFound = true
			}
			out = append(out, item)
		}
	}
	return out
}

func scanVersions(opts Options, tool, activeTarget string) []Install {
	var roots []string
	switch tool {
	case ToolClaude:
		roots = []string{filepath.Join(opts.HomeDir, ".local", "share", "claude", "versions")}
	case ToolCodex:
		roots = []string{
			filepath.Join(opts.HomeDir, ".codex", "packages", "standalone", "releases"),
			filepath.Join(opts.HomeDir, ".codex", "packages", "app-server-daemon", "releases"),
		}
	}
	var out []Install
	for _, root := range roots {
		entries, _ := os.ReadDir(root)
		for _, entry := range entries {
			path := filepath.Join(root, entry.Name())
			resolved, err := filepath.EvalSymlinks(path)
			if err != nil {
				resolved = path
			}
			out = append(out, Install{
				Tool:    tool,
				Kind:    KindVersion,
				Source:  SourceNative,
				Path:    path,
				Version: strings.SplitN(entry.Name(), "-", 2)[0],
				Active:  activeTarget != "" && (activeTarget == resolved || strings.HasPrefix(activeTarget, resolved+string(filepath.Separator))),
			})
		}
	}
	return out
}

func scanPackages(opts Options, tool string) []Install {
	pkg := map[string]string{ToolClaude: "@anthropic-ai/claude-code", ToolCodex: "@openai/codex"}[tool]
	cask := map[string]string{ToolClaude: "claude-code", ToolCodex: "codex"}[tool]
	var out []Install
	for _, prefix := range opts.PrefixDirs {
		dir := filepath.Join(prefix, "lib", "node_modules", filepath.FromSlash(pkg))
		if version := packageVersion(filepath.Join(dir, "package.json")); version != "" {
			out = append(out, Install{Tool: tool, Kind: KindPackage, Source: SourceNPM, Path: dir, Version: version})
		}
		for _, store := range []string{"Caskroom", "Cellar"} {
			entries, _ := os.ReadDir(filepath.Join(prefix, store, cask))
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".") {
					continue
				}
				out = append(out, Install{
					Tool:    tool,
					Kind:    KindCask,
					Source:  SourceHomebrew,
					Path:    filepath.Join(prefix, store, cask, entry.Name()),
					Version: strings.SplitN(entry.Name(), ",", 2)[0],
				})
			}
		}
	}
	return out
}

func scanAppBundles(opts Options, tool string) []Install {
	var out []Install
	switch tool {
	case ToolClaude:
		root := filepath.Join(opts.HomeDir, "Library", "Application Support", "Claude", "claude-code")
		entries, _ := os.ReadDir(root)
		for _, entry := range entries {
			if entry.IsDir() {
				out = append(out, Install{Tool: tool, Kind: KindAppBundle, Source: SourceApp, Path: filepath.Join(root, entry.Name()), Version: entry.Name()})
			}
		}
	case ToolCodex:
		for _, app := range []string{"ChatGPT.app", "Codex.app"} {
			dir := filepath.Join(opts.AppsDir, app, "Contents", "Resources", "codex-cli")
			if version := packageVersion(filepath.Join(dir, "codex-package.json")); version != "" {
				out = append(out, Install{Tool: tool, Kind: KindAppBundle, Source: SourceApp, Path: dir, Version: version})
			}
		}
	}
	return out
}

func classifySource(target string) string {
	slash := filepath.ToSlash(target)
	switch {
	case strings.Contains(slash, "/.local/share/claude/versions/"), strings.Contains(slash, "/.codex/packages/"):
		return SourceNative
	case strings.Contains(slash, "/node_modules/"):
		return SourceNPM
	case strings.Contains(slash, "/Caskroom/"), strings.Contains(slash, "/Cellar/"):
		return SourceHomebrew
	case strings.Contains(slash, ".app/Contents/"):
		return SourceApp
	}
	return SourceUnknown
}

var versionPattern = regexp.MustCompile(`(?:^|/)(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)(?:-[a-z0-9_]+-apple-darwin)?(?:/|$)`)

func versionFromPath(path string) string {
	if match := versionPattern.FindStringSubmatch(filepath.ToSlash(path)); match != nil {
		return strings.TrimSuffix(strings.SplitN(match[1], "-aarch64", 2)[0], "-x86_64")
	}
	return ""
}

func packageVersion(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var pkg struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return ""
	}
	return pkg.Version
}

// --- processes ---

type psRow struct {
	pid, ppid int
	etime     string
	rssKB     int
	exe       string
}

func listProcesses(opts Options) (map[int]psRow, map[int]string) {
	rows := map[int]psRow{}
	args := map[int]string{}
	if out, err := opts.Run("ps", "-axww", "-o", "pid=,ppid=,etime=,rss=,comm="); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			pid, _ := strconv.Atoi(fields[0])
			ppid, _ := strconv.Atoi(fields[1])
			rss, _ := strconv.Atoi(fields[3])
			rows[pid] = psRow{pid: pid, ppid: ppid, etime: fields[2], rssKB: rss, exe: restAfterFields(line, 4)}
		}
	}
	if out, err := opts.Run("ps", "-axww", "-o", "pid=,args="); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			pid, _ := strconv.Atoi(fields[0])
			args[pid] = restAfterFields(line, 1)
		}
	}
	return rows, args
}

// restAfterFields returns the line from its n-th whitespace-separated field on, keeping inner spaces.
func restAfterFields(line string, n int) string {
	rest := strings.TrimLeft(line, " \t")
	for i := 0; i < n; i++ {
		idx := strings.IndexAny(rest, " \t")
		if idx < 0 {
			return ""
		}
		rest = strings.TrimLeft(rest[idx:], " \t")
	}
	return strings.TrimRight(rest, " \t\r")
}

func toolForExecutable(exe string) string {
	lower := strings.ToLower(exe)
	if strings.Contains(lower, "/frameworks/") || strings.Contains(lower, "/contents/helpers/") {
		return ""
	}
	base := strings.ToLower(filepath.Base(exe))
	switch {
	case strings.Contains(lower, "codex"):
		return ToolCodex
	case strings.Contains(base, "claude") || strings.Contains(lower, "/claude/versions/") || strings.Contains(lower, "/claude-code/"):
		return ToolClaude
	}
	return ""
}

var subcommandPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// subcommand keeps only the first bare word after the executable, so flags, values, paths and
// secrets on the command line are never retained.
func subcommand(exe, args string) string {
	rest := ""
	if strings.HasPrefix(args, exe) {
		rest = args[len(exe):]
	} else if idx := strings.IndexAny(args, " \t"); idx >= 0 {
		rest = args[idx:]
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 || !subcommandPattern.MatchString(fields[0]) {
		return ""
	}
	return fields[0]
}

func scanProcesses(opts Options, labels map[int]launchdEntry) []Process {
	rows, args := listProcesses(opts)
	var out []Process
	for _, row := range rows {
		tool := toolForExecutable(row.exe)
		if tool == "" {
			continue
		}
		supervisor, kind := superviseOf(row.pid, rows, labels)
		proc := Process{
			PID:            row.pid,
			PPID:           row.ppid,
			Tool:           tool,
			Executable:     row.exe,
			Subcommand:     subcommand(row.exe, args[row.pid]),
			Uptime:         row.etime,
			UptimeSeconds:  parseEtime(row.etime),
			RSSMB:          row.rssKB / 1024,
			Supervisor:     supervisor,
			SupervisorKind: kind,
		}
		if filepath.IsAbs(row.exe) {
			if _, err := os.Stat(row.exe); err != nil {
				proc.ExecutableMissing = true
			}
		}
		out = append(out, proc)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Tool != out[j].Tool {
			return out[i].Tool < out[j].Tool
		}
		return out[i].PID < out[j].PID
	})
	return out
}

// superviseOf walks up the parent chain to the first launchd job, or to an orphan root.
func superviseOf(pid int, rows map[int]psRow, labels map[int]launchdEntry) (string, string) {
	cur := pid
	for depth := 0; depth < 64; depth++ {
		if entry, ok := labels[cur]; ok {
			if strings.HasPrefix(entry.label, "application.") {
				return entry.label, SupervisorApp
			}
			return entry.label, SupervisorLaunchd
		}
		row, ok := rows[cur]
		if !ok {
			break
		}
		if row.ppid <= 1 {
			return filepath.Base(row.exe), SupervisorUnmanaged
		}
		cur = row.ppid
	}
	return "", SupervisorUnmanaged
}

func parseEtime(value string) int64 {
	days := int64(0)
	if idx := strings.Index(value, "-"); idx >= 0 {
		days, _ = strconv.ParseInt(value[:idx], 10, 64)
		value = value[idx+1:]
	}
	parts := strings.Split(value, ":")
	total := int64(0)
	for _, part := range parts {
		n, _ := strconv.ParseInt(part, 10, 64)
		total = total*60 + n
	}
	return days*86400 + total
}

// --- launchd ---

type launchdEntry struct {
	label  string
	status *int
}

func launchdLabels(opts Options) map[int]launchdEntry {
	byPID := map[int]launchdEntry{}
	for _, job := range launchctlList(opts) {
		if job.pid > 0 {
			byPID[job.pid] = launchdEntry{label: job.label, status: job.status}
		}
	}
	return byPID
}

type launchctlJob struct {
	pid    int
	status *int
	label  string
}

func launchctlList(opts Options) []launchctlJob {
	out, err := opts.Run("launchctl", "list")
	if err != nil {
		return nil
	}
	var jobs []launchctlJob
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 || fields[2] == "Label" {
			continue
		}
		job := launchctlJob{label: fields[2]}
		job.pid, _ = strconv.Atoi(fields[0])
		if status, err := strconv.Atoi(fields[1]); err == nil {
			job.status = &status
		}
		jobs = append(jobs, job)
	}
	return jobs
}

type plistJob struct {
	Label             string      `json:"Label"`
	Program           string      `json:"Program"`
	ProgramArguments  []string    `json:"ProgramArguments"`
	StartInterval     int         `json:"StartInterval"`
	KeepAlive         interface{} `json:"KeepAlive"`
	StandardErrorPath string      `json:"StandardErrorPath"`
}

func scanLaunchJobs(opts Options, labels map[int]launchdEntry, procs []Process) []LaunchJob {
	supervising := map[string][]string{}
	for _, proc := range procs {
		if proc.SupervisorKind == SupervisorLaunchd {
			supervising[proc.Supervisor] = appendUnique(supervising[proc.Supervisor], proc.Tool)
		}
	}
	state := map[string]launchctlJob{}
	for _, job := range launchctlList(opts) {
		state[job.label] = job
	}
	paths, _ := filepath.Glob(filepath.Join(opts.HomeDir, "Library", "LaunchAgents", "*.plist"))
	var out []LaunchJob
	for _, path := range paths {
		data, err := opts.Run("plutil", "-convert", "json", "-o", "-", path)
		if err != nil {
			continue
		}
		var job plistJob
		if json.Unmarshal(data, &job) != nil || job.Label == "" {
			continue
		}
		program := job.Program
		if program == "" && len(job.ProgramArguments) > 0 {
			program = job.ProgramArguments[0]
		}
		mentioned := []string{}
		joined := strings.ToLower(program + " " + strings.Join(job.ProgramArguments, " "))
		for _, tool := range tools {
			if strings.Contains(joined, tool) {
				mentioned = append(mentioned, tool)
			}
		}
		for _, tool := range supervising[job.Label] {
			mentioned = appendUnique(mentioned, tool)
		}
		if len(mentioned) == 0 {
			continue
		}
		item := LaunchJob{Label: job.Label, Path: path, Program: program, Tools: mentioned, StartInterval: job.StartInterval}
		switch keep := job.KeepAlive.(type) {
		case bool:
			item.KeepAlive = keep
		case map[string]interface{}:
			item.KeepAlive = len(keep) > 0
		}
		if current, ok := state[job.Label]; ok {
			item.PID = current.pid
			item.Running = current.pid > 0
			item.LastExit = current.status
		}
		item.RecentErrors = recentErrorLines(job.StandardErrorPath, opts.Now())
		out = append(out, item)
	}
	return out
}

// recentErrorLines counts lines mentioning an error near the end of a log written in the last
// hour. Only the count is kept; log content never leaves this function.
func recentErrorLines(path string, now time.Time) int {
	if path == "" {
		return 0
	}
	info, err := os.Stat(path)
	if err != nil || now.Sub(info.ModTime()) > time.Hour {
		return 0
	}
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	const tail = 16 << 10
	if info.Size() > tail {
		_, _ = file.Seek(info.Size()-tail, 0)
	}
	count := 0
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for scanner.Scan() {
		if bytes.Contains(bytes.ToLower(scanner.Bytes()), []byte("error")) {
			count++
		}
	}
	return count
}

// --- plugins ---

func scanPlugins(opts Options) []Plugin {
	return append(claudePlugins(opts), codexPlugins(opts)...)
}

func claudePlugins(opts Options) []Plugin {
	var installed struct {
		Plugins map[string][]struct {
			Scope       string `json:"scope"`
			InstallPath string `json:"installPath"`
			Version     string `json:"version"`
		} `json:"plugins"`
	}
	data, err := os.ReadFile(filepath.Join(opts.HomeDir, ".claude", "plugins", "installed_plugins.json"))
	if err != nil || json.Unmarshal(data, &installed) != nil {
		return nil
	}
	var settings struct {
		EnabledPlugins map[string]bool `json:"enabledPlugins"`
	}
	if data, err := os.ReadFile(filepath.Join(opts.HomeDir, ".claude", "settings.json")); err == nil {
		_ = json.Unmarshal(data, &settings)
	}
	var out []Plugin
	for id, installs := range installed.Plugins {
		for _, inst := range installs {
			name, market, _ := strings.Cut(id, "@")
			enabled, ok := settings.EnabledPlugins[id]
			out = append(out, Plugin{
				Runtime:     "claude_code",
				Name:        name,
				Marketplace: market,
				Version:     inst.Version,
				Scope:       inst.Scope,
				Enabled:     !ok || enabled,
				MCPServers:  pluginMCPServers(inst.InstallPath),
			})
		}
	}
	sortPlugins(out)
	return out
}

func pluginMCPServers(root string) []PluginMCP {
	if root == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(root, ".mcp.json"))
	if err != nil {
		return nil
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(data, &doc) != nil {
		return nil
	}
	if inner, ok := doc["mcpServers"]; ok {
		doc = map[string]json.RawMessage{}
		if json.Unmarshal(inner, &doc) != nil {
			return nil
		}
	}
	var out []PluginMCP
	for name, raw := range doc {
		var def struct {
			Type    string   `json:"type"`
			URL     string   `json:"url"`
			Command string   `json:"command"`
			Args    []string `json:"args"`
		}
		if json.Unmarshal(raw, &def) != nil {
			continue
		}
		item := PluginMCP{Name: name, Transport: def.Type}
		if item.Transport == "" {
			item.Transport = "stdio"
			if def.URL != "" {
				item.Transport = "http"
			}
		}
		if def.Command != "" {
			item.Command = filepath.Base(def.Command)
			item.ViaSSH = launchesSSH(root, def.Command, def.Args)
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var sshPattern = regexp.MustCompile(`(?m)^\s*(?:exec\s+)?ssh\s`)

// launchesSSH reports whether a stdio MCP command is ssh, or a shell script that execs ssh.
func launchesSSH(root, command string, args []string) bool {
	if filepath.Base(command) == "ssh" {
		return true
	}
	switch filepath.Base(command) {
	case "bash", "sh", "zsh":
	default:
		return false
	}
	if len(args) == 0 {
		return false
	}
	script := strings.ReplaceAll(args[0], "${CLAUDE_PLUGIN_ROOT}", root)
	data, err := os.ReadFile(script)
	if err != nil {
		return false
	}
	return sshPattern.Match(data)
}

func codexPlugins(opts Options) []Plugin {
	data, err := os.ReadFile(filepath.Join(opts.HomeDir, ".codex", "config.toml"))
	if err != nil {
		return nil
	}
	var config struct {
		Plugins map[string]struct {
			Enabled *bool `toml:"enabled"`
		} `toml:"plugins"`
	}
	if toml.Unmarshal(data, &config) != nil {
		return nil
	}
	var out []Plugin
	for id, plugin := range config.Plugins {
		name, market, _ := strings.Cut(id, "@")
		out = append(out, Plugin{Runtime: "codex_cli", Name: name, Marketplace: market, Enabled: plugin.Enabled == nil || *plugin.Enabled})
	}
	sortPlugins(out)
	return out
}

func sortPlugins(items []Plugin) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Marketplace != items[j].Marketplace {
			return items[i].Marketplace < items[j].Marketplace
		}
		return items[i].Name < items[j].Name
	})
}

// --- warnings ---

func warnings(opts Options, report Report) []Warning {
	var out []Warning
	for _, tool := range tools {
		sources := []string{}
		for _, item := range report.Installs {
			if item.Tool != tool || item.Broken || item.Kind == KindVersion || item.Kind == KindAppBundle {
				continue
			}
			sources = appendUnique(sources, item.Source)
		}
		if len(sources) > 1 {
			sort.Strings(sources)
			out = append(out, Warning{Kind: "duplicate_install", Subject: tool, Message: tool + " is installed from more than one source: " + strings.Join(sources, ", ")})
		}
	}
	for _, item := range report.Installs {
		if item.Broken {
			out = append(out, Warning{Kind: "broken_link", Subject: item.Path, Message: "points to a missing file: " + item.Target})
		}
	}
	for _, proc := range report.Processes {
		subject := strconv.Itoa(proc.PID) + " " + filepath.Base(proc.Executable)
		if proc.Subcommand != "" {
			subject += " " + proc.Subcommand
		}
		if proc.ExecutableMissing {
			out = append(out, Warning{Kind: "deleted_executable", Subject: subject, Message: "running from an executable that no longer exists"})
		}
		if proc.SupervisorKind == SupervisorUnmanaged {
			out = append(out, Warning{Kind: "unmanaged_process", Subject: subject, Message: "not supervised by launchd or an app (root: " + proc.Supervisor + "); it will not come back after a restart"})
		}
		if proc.SupervisorKind != SupervisorLaunchd && proc.UptimeSeconds > int64(opts.StaleAfter/time.Second) {
			out = append(out, Warning{Kind: "long_running", Subject: subject, Message: "running for " + proc.Uptime})
		}
	}
	for _, plugin := range report.Plugins {
		for _, server := range plugin.MCPServers {
			if server.ViaSSH && plugin.Enabled {
				out = append(out, Warning{Kind: "ssh_mcp", Subject: plugin.Name + "/" + server.Name, Message: "MCP server runs over SSH stdio; each client session holds its own SSH connection"})
			}
		}
	}
	for _, job := range report.LaunchJobs {
		if !job.Running && job.LastExit != nil && *job.LastExit != 0 {
			out = append(out, Warning{Kind: "job_failing", Subject: job.Label, Message: "last exit status " + strconv.Itoa(*job.LastExit)})
		}
		if job.RecentErrors >= 5 {
			out = append(out, Warning{Kind: "job_errors", Subject: job.Label, Message: strconv.Itoa(job.RecentErrors) + " error lines in the last hour of its error log"})
		}
	}
	return out
}

func appendUnique(items []string, value string) []string {
	for _, item := range items {
		if item == value {
			return items
		}
	}
	return append(items, value)
}

func uniqueStrings(items []string) []string {
	var out []string
	for _, item := range items {
		if item != "" {
			out = appendUnique(out, item)
		}
	}
	return out
}
