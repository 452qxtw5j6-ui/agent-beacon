package cmd

import (
	"github.com/spf13/cobra"
)

var codexAssistantResponseCmd = &cobra.Command{
	Use:    "codex-assistant-response",
	Short:  "Record the final assistant reply of a Codex turn",
	Hidden: true,
	Run:    runCodexAssistantResponse,
}

func init() {
	rootCmd.AddCommand(codexAssistantResponseCmd)
}

// runCodexAssistantResponse is Codex's Stop hook, and it records one thing: the turn's final reply,
// which Codex's Stop payload documents as `last_assistant_message`.
//
// Codex's OTLP export carries prompts, tool decisions, tool results and token usage but never what
// the agent said, so before this the reply reached the log only when someone ran
// `beacon endpoint codex sync`. It is a dedicated command rather than the shared `stop` for the
// reason Codex has no other generic hooks: OTLP already reports the turn, and a second completion
// event from a hook would duplicate it. Codex reads a Stop hook's stdout as JSON, so every path
// answers `{}`, which continues the turn's normal end.
func runCodexAssistantResponse(cmd *cobra.Command, args []string) {
	input, err := readStdinJSON()
	if err != nil || platformFlag != "codex" {
		outputJSON(emptyResponse)
		return
	}
	sessionID := resolveSessionID(input, "codex")
	logger := newHookLogger("codex-assistant-response", "codex", sessionID)
	fields := sessionFieldsForPlatform(sessionID, input, "codex")
	emitAssistantMessage(logger, input, fields, getFirstStr(input, "last_assistant_message"))
	outputJSON(emptyResponse)
}
