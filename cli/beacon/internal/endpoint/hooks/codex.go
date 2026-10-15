package hooks

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/codexsession"
)

type CodexOptions struct {
	Level    Level
	LogPath  string
	UserMode bool
}

type CodexStatus struct {
	Installed  bool   `json:"installed"`
	BinaryPath string `json:"binary_path,omitempty"`
	HooksPath  string `json:"hooks_path,omitempty"`
	Message    string `json:"message,omitempty"`
}

var codexRuntime = hookRuntime{
	displayName: "Codex CLI",
	configPath:  codexHooksPath,
	install:     installCodexHooks,
	uninstall:   removeCodexEndpointHooks,
	isInstalled: isCodexInstalledAt,
}

func InstallCodex(opts CodexOptions) (CodexStatus, error) {
	status, err := installRuntimeHooks(codexRuntime, RuntimeOptions(opts))
	if err != nil {
		return CodexStatus{}, err
	}
	return codexStatusFromRuntime(status), nil
}

func UninstallCodex(opts CodexOptions) (CodexStatus, error) {
	status, err := uninstallRuntimeHooks(codexRuntime, RuntimeOptions(opts))
	if err != nil {
		return CodexStatus{}, err
	}
	return codexStatusFromRuntime(status), nil
}

func CodexHookStatus(opts CodexOptions) CodexStatus {
	return codexStatusFromRuntime(runtimeHookStatus(codexRuntime, RuntimeOptions(opts)))
}

func IsCodexInstalled(opts CodexOptions) bool {
	return isRuntimeInstalled(codexRuntime, RuntimeOptions(opts))
}

func codexStatusFromRuntime(status runtimeStatus) CodexStatus {
	return CodexStatus{
		Installed:  status.Installed,
		BinaryPath: status.BinaryPath,
		HooksPath:  status.ConfigPath,
		Message:    status.Message,
	}
}

func installCodexHooks(path, binaryPath, logPath, configPath string) error {
	prefix := endpointCommandPrefix("codex", binaryPath, logPath, configPath)
	// Hooks supply only what Codex's OTLP export lacks: the OS-user session context, and the turn's
	// final reply, which Codex's Stop payload carries as last_assistant_message and no span or log
	// does. Both are dedicated commands rather than the generic ones, because OTLP already reports
	// the session, prompts, tools and turn. Inventory used to ride SessionStart and
	// UserPromptSubmit here; it is written by the scheduled inventory job now.
	endpointHooks := map[string]settingsHookGroup{
		"SessionStart": {Hooks: []settingsHookRef{
			{Type: "command", Command: prefix + " codex-session-context", Timeout: 10},
		}},
		"Stop": {Hooks: []settingsHookRef{
			{Type: "command", Command: prefix + " codex-assistant-response", Timeout: 10},
		}},
	}
	return installSettingsEndpointHooks(path, "codex", endpointHooks)
}

func removeCodexEndpointHooks(path string) (bool, error) {
	return removeSettingsEndpointHooks(path, "codex")
}

func isCodexInstalledAt(path string) bool {
	return isSettingsEndpointInstalledAt(path, "codex")
}

func codexHooksPath(level Level) (string, error) {
	switch level {
	case "", LevelUser:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir, err := codexsession.HomeDir(home)
		if err != nil {
			return "", err
		}
		return filepath.Join(dir, "hooks.json"), nil
	case LevelProject:
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, ".codex", "hooks.json"), nil
	default:
		return "", fmt.Errorf("unknown hook level %q", level)
	}
}
