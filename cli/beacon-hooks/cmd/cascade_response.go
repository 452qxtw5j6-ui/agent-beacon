package cmd

import (
	"github.com/spf13/cobra"
)

var cascadeResponseCmd = &cobra.Command{
	Use:    "cascade-response",
	Short:  "Record a Cascade response for local endpoint telemetry",
	Hidden: true,
	Run:    runCascadeResponse,
}

func init() {
	rootCmd.AddCommand(cascadeResponseCmd)
}

// runCascadeResponse is Devin Desktop's post_cascade_response hook. Cascade runs it after it
// finishes answering a prompt, with `tool_info.response`: the Markdown of everything Cascade said
// since the user's last input. It is the only place a Cascade reply reaches a hook; without it a
// Devin Desktop session recorded prompts and tool calls but never what the agent answered.
//
// The text is Cascade's own rendering of the turn, so it can include planner notes and one-line
// summaries of the actions Cascade took ("*Created file ...*") around the answer. It is recorded as
// Cascade reports it rather than parsed apart, because the format is not documented beyond being
// Markdown, and a parser guessing at it could drop the answer.
func runCascadeResponse(cmd *cobra.Command, args []string) {
	input, err := readStdinJSON()
	if err != nil || !isCascadePlatform(platformFlag) {
		outputJSON(hookNoopResponse())
		return
	}
	info := cascadeToolInfo(input)
	response := getFirstStr(info, "response")
	sessionID := resolveSessionID(input, platformFlag)
	logger := newHookLogger("cascade-response", platformFlag, sessionID)
	// raw.cascade keeps the whole Cascade payload on every event of this runtime. The response is
	// already the event's gen_ai output, so the raw copy leaves it out instead of storing it twice.
	payload := cascadePayloadWithoutResponse(input)
	emitAssistantMessage(logger, payload, cascadeMetadataFields(sessionID, payload), response)
	outputJSON(hookNoopResponse())
}

// cascadePayloadWithoutResponse is input with tool_info.response removed, leaving input unchanged.
func cascadePayloadWithoutResponse(input map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		out[key] = value
	}
	for _, key := range []string{"tool_info", "toolInfo"} {
		info, ok := input[key].(map[string]interface{})
		if !ok {
			continue
		}
		trimmed := make(map[string]interface{}, len(info))
		for k, v := range info {
			if k != "response" {
				trimmed[k] = v
			}
		}
		out[key] = trimmed
	}
	return out
}
