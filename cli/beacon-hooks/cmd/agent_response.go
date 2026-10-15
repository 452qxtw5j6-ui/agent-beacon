package cmd

import (
	"github.com/spf13/cobra"
)

var agentResponseCmd = &cobra.Command{
	Use:   "agent-response",
	Short: "Record the agent's reply for local endpoint telemetry",
	Long: `afterAgentResponse hook - triggered when the agent finishes an assistant message.
Records the reply text as local endpoint telemetry.`,
	Run: runAgentResponse,
}

func init() {
	rootCmd.AddCommand(agentResponseCmd)
}

// runAgentResponse is Cursor's afterAgentResponse hook. Cursor documents one event-specific field,
// `text`, holding the assistant's reply; without this hook a live Cursor session recorded the
// reasoning (afterAgentThought) and every tool call but not what the agent answered.
//
// `text` is read only for Cursor. It is a generic key, and on another runtime's payload it could be
// the prompt or a tool's output; a reply recorded from the wrong field would be a fabricated
// message in a security log.
func runAgentResponse(cmd *cobra.Command, args []string) {
	input, err := readStdinJSON()
	if err != nil {
		outputJSON(hookNoopResponse())
		return
	}
	if platformFlag == "cursor" {
		sessionID := resolveSessionID(input, platformFlag)
		logger := newHookLogger("agent-response", platformFlag, sessionID)
		emitAssistantMessage(logger, input, sessionFields(sessionID, input), getFirstStr(input, "text"))
	}
	outputJSON(hookNoopResponse())
}
