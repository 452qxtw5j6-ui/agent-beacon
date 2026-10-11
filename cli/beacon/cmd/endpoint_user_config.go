package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	endpointconfig "github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/config"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/harness"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/writer"
	"github.com/spf13/cobra"
)

var endpointUserConfigCmd = &cobra.Command{
	Use:    "user-config",
	Short:  "Repair active user endpoint runtime configuration",
	Hidden: true,
}

var endpointUserConfigRepairInstalledCmd = &cobra.Command{
	Use:          "repair-installed",
	Short:        "Repair active console user runtime configuration for a system endpoint",
	Hidden:       true,
	SilenceUsage: true,
	RunE:         runEndpointUserConfigRepairInstalled,
}

type endpointUserConfigRepairResult struct {
	User                string   `json:"user,omitempty"`
	HomeDir             string   `json:"home_dir,omitempty"`
	RuntimeLogPath      string   `json:"runtime_log_path,omitempty"`
	NativeConfigTargets []string `json:"native_config_targets,omitempty"`
	NativeConfigPaths   []string `json:"native_config_paths,omitempty"`
	HookTargets         []string `json:"hook_targets,omitempty"`
	SkippedReason       string   `json:"skipped_reason,omitempty"`
}

type userConfigTargets struct {
	native []string
	hooks  []string
}

var loadConfigForUserRepair = loadConfigForMode

func runEndpointUserConfigRepairInstalled(cmd *cobra.Command, args []string) error {
	result, err := repairInstalledEndpointUserConfig()
	if endpointOpts.jsonOutput {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}
	return err
}

func repairInstalledEndpointUserConfig() (endpointUserConfigRepairResult, error) {
	if endpointUserMode() {
		return endpointUserConfigRepairResult{SkippedReason: "requires_system_endpoint"}, fmt.Errorf("endpoint user-config repair-installed is intended for system endpoint installs; pass --system")
	}
	info, ok, err := activeConsoleUser()
	if err != nil {
		return endpointUserConfigRepairResult{}, err
	}
	if !ok {
		return endpointUserConfigRepairResult{SkippedReason: "no_active_console_user"}, nil
	}

	cfg := loadConfigForUserRepair(false, endpointOpts.logPath)
	if cfg.LogPath == "" {
		cfg.LogPath = writer.DefaultPath(false)
	}
	targets, err := resolveUserConfigTargets(splitCSV(endpointOpts.hookHarnesses))
	if err != nil {
		return endpointUserConfigRepairResult{}, err
	}
	if len(targets.native) == 0 && len(targets.hooks) == 0 {
		targets = userConfigTargets{
			native: []string{"claude", "codex"},
			hooks:  []string{"claude", "codex", "cursor"},
		}
	}

	nativeTargets, nativePaths, err := repairNativeRuntimeConfigForUser(info, cfg, targets.native)
	if err != nil {
		return endpointUserConfigRepairResult{}, err
	}
	var hookTargets []string
	if len(targets.hooks) > 0 {
		hookTargets, err = repairHookTargetsForUser(info, cfg.LogPath, targets.hooks)
		if err != nil {
			return endpointUserConfigRepairResult{}, err
		}
	}
	return endpointUserConfigRepairResult{
		User:                info.Username,
		HomeDir:             info.HomeDir,
		RuntimeLogPath:      cfg.LogPath,
		NativeConfigTargets: nativeTargets,
		NativeConfigPaths:   nativePaths,
		HookTargets:         hookTargets,
	}, nil
}

func resolveUserConfigTargets(values []string) (userConfigTargets, error) {
	seenNative := map[string]bool{}
	seenHooks := map[string]bool{}
	targets := userConfigTargets{native: []string{}, hooks: []string{}}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		endpointTarget, endpointOK := normalizeEndpointTarget(value)
		hookTarget, hookOK := normalizeHookTarget(value)
		if !endpointOK && !hookOK {
			return userConfigTargets{}, fmt.Errorf("unsupported user config harness %q", value)
		}
		if endpointOK && endpointTarget.Kind == endpointTargetOTLP {
			switch endpointTarget.Name {
			case "claude", "codex", "gemini":
				if !seenNative[endpointTarget.Name] {
					targets.native = append(targets.native, endpointTarget.Name)
					seenNative[endpointTarget.Name] = true
				}
			}
		}
		if hookOK && !seenHooks[hookTarget] {
			targets.hooks = append(targets.hooks, hookTarget)
			seenHooks[hookTarget] = true
		}
	}
	return targets, nil
}

// nativeConfigOptions is what the native runtime configs are rendered from. It is passed to the
// child process on its command line, so it holds only plain values.
type nativeConfigOptions struct {
	GRPCPort            int
	CaptureModelContext bool
}

// nativeConfigResult is what apply-native reports back to the root-side repair.
type nativeConfigResult struct {
	Targets []string `json:"native_config_targets"`
	Paths   []string `json:"native_config_paths"`
}

var (
	// writeAsConsoleUser reports whether native config must be written by a child process running
	// as the console user rather than by this process. True for root on POSIX: see
	// repairNativeRuntimeConfigForUser.
	writeAsConsoleUser    = defaultWriteAsConsoleUser
	runNativeConfigAsUser = defaultRunNativeConfigAsUser
)

func defaultWriteAsConsoleUser() bool {
	return runtime.GOOS != "windows" && os.Geteuid() == 0
}

// repairNativeRuntimeConfigForUser points the console user's Claude Code, Codex and Gemini configs
// at the collector.
//
// A system install runs this as root, and root must not write into a home directory its owner
// controls. The writers read and write paths such as ~/.claude/settings.json and their backups with
// ordinary file calls, which follow symlinks: with ~/.claude linked to /etc, or settings.json to
// /etc/shadow, a root writer edits or copies system files, and the chown that used to hand the
// results back to the user then gave them ownership of the target. A package postinstall and the
// scheduled updater both run this unattended, so any code running as that user -- a package script,
// a prompt-injected agent -- could turn the next upgrade into root.
//
// So as root on POSIX the work runs in a child process that has dropped to the user, through the
// same runuser/sudo launcher hook repair uses. Every file is then created by the user, with the
// user's own permissions, and nothing needs chowning; a symlink the user planted can only lead to
// files they could already write. Windows keeps the in-process path: an elevated process there
// writes into a profile whose ACL already grants its owner full control (see
// runHookRepairInProfile).
func repairNativeRuntimeConfigForUser(info consoleUserInfo, cfg endpointconfig.Config, targets []string) ([]string, []string, error) {
	if len(targets) == 0 {
		return nil, nil, nil
	}
	opts := nativeConfigOptions{GRPCPort: cfg.Collector.GRPCPort, CaptureModelContext: cfg.ClaudeCaptureModelContext}
	var result nativeConfigResult
	var err error
	if writeAsConsoleUser() {
		result, err = runNativeConfigAsUser(info, targets, opts)
	} else {
		result, err = withUserHome(info.HomeDir, func() (nativeConfigResult, error) {
			return applyNativeRuntimeConfig(targets, opts)
		})
	}
	return result.Targets, result.Paths, err
}

// applyNativeRuntimeConfig writes the native runtime configs into the home directory of whoever
// runs it.
func applyNativeRuntimeConfig(targets []string, opts nativeConfigOptions) (nativeConfigResult, error) {
	grpcEndpoint := fmt.Sprintf("http://127.0.0.1:%d", opts.GRPCPort)
	seen := map[string]bool{}
	result := nativeConfigResult{Targets: []string{}, Paths: []string{}}
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if seen[target] {
			continue
		}
		var path string
		var err error
		switch target {
		case "claude":
			path, err = harness.ConfigureClaude(harness.ConfigureOptions{Endpoint: grpcEndpoint, UserMode: true, CaptureModelContext: opts.CaptureModelContext})
		case "codex":
			path, err = harness.ConfigureCodex(harness.ConfigureOptions{Endpoint: grpcEndpoint, UserMode: true})
		case "gemini":
			path, err = harness.ConfigureGemini(harness.ConfigureOptions{Endpoint: grpcEndpoint, UserMode: true})
		default:
			continue
		}
		if err != nil {
			return result, err
		}
		if err := collapseUserConfigBackups(path); err != nil {
			return result, err
		}
		result.Targets = append(result.Targets, target)
		result.Paths = append(result.Paths, path)
		seen[target] = true
	}
	return result, nil
}

var endpointUserConfigApplyNativeCmd = &cobra.Command{
	Use:          "apply-native",
	Short:        "Point this user's native runtime configs at the local collector",
	Hidden:       true,
	SilenceUsage: true,
	Args:         cobra.NoArgs,
	RunE:         runEndpointUserConfigApplyNative,
}

var applyNativeOpts struct {
	harnesses           string
	grpcPort            int
	captureModelContext bool
}

// runEndpointUserConfigApplyNative is the child side of a root repair: it runs as the console user
// and writes only into that user's own home.
func runEndpointUserConfigApplyNative(cmd *cobra.Command, _ []string) error {
	if applyNativeOpts.grpcPort <= 0 || applyNativeOpts.grpcPort > 65535 {
		return fmt.Errorf("--grpc-port must be a TCP port, got %d", applyNativeOpts.grpcPort)
	}
	result, err := applyNativeRuntimeConfig(splitCSV(applyNativeOpts.harnesses), nativeConfigOptions{
		GRPCPort:            applyNativeOpts.grpcPort,
		CaptureModelContext: applyNativeOpts.captureModelContext,
	})
	if err != nil {
		return err
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
}

func defaultRunNativeConfigAsUser(info consoleUserInfo, targets []string, opts nativeConfigOptions) (nativeConfigResult, error) {
	bin, err := os.Executable()
	if err != nil {
		return nativeConfigResult{}, err
	}
	args := []string{"endpoint", "user-config", "apply-native",
		"--harness", strings.Join(targets, ","),
		"--grpc-port", strconv.Itoa(opts.GRPCPort)}
	if opts.CaptureModelContext {
		args = append(args, "--claude-capture-model-context")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := consoleUserCommand(ctx, info, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nativeConfigResult{}, fmt.Errorf("configure runtimes for %s: %s: %w", info.Username, strings.TrimSpace(stderr.String()), err)
	}
	var result nativeConfigResult
	if err := json.Unmarshal(out, &result); err != nil {
		return nativeConfigResult{}, fmt.Errorf("configure runtimes for %s: read result: %w", info.Username, err)
	}
	return result, nil
}

func collapseUserConfigBackups(path string) error {
	matches, err := filepath.Glob(path + ".beacon.*.bak")
	if err != nil || len(matches) == 0 {
		return err
	}
	sort.Strings(matches)
	latest := matches[len(matches)-1]
	data, err := os.ReadFile(latest)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".beacon.bak", data, 0600); err != nil {
		return err
	}
	for _, match := range matches {
		if err := os.Remove(match); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
