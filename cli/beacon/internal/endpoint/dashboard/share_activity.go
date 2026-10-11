package dashboard

import (
	"regexp"
	"strings"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/schema"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// shareActivity decides which of a session's events count as activity that makes its shared trace
// stale. Besides Beacon's own bookkeeping, a share made from inside the session is followed by
// events about the share itself: the runtime's events for the `beacon share` command (its call and
// its completion, matched by gen_ai.tool.call.id) and the agent's reply about it. Counting those
// would leave a session shared or refreshed from inside itself stale forever. Anything else -- a
// new prompt, another tool call, a file write, a command that is not the share -- still counts.
//
// It is state carried across a session's events in log order, so the trace projection persists it
// with the rest of its running state (traceAggregateState).
type shareActivity struct {
	// ShareCalls are the tool call ids of `beacon share` invocations.
	ShareCalls map[string]bool `json:"share_calls,omitempty"`
	// SharePrompts are the turns (prompt.id) that ran `beacon share`.
	SharePrompts map[string]bool `json:"share_prompts,omitempty"`
	// QuietSinceShare is true from a session.shared record until the next event that counts.
	QuietSinceShare bool `json:"quiet_since_share,omitempty"`
}

// beaconShareCommand matches a shell command that runs `beacon share`, with any subcommand or
// flags, as a whole word (`beacon share`, `/opt/beacon/bin/beacon share refresh ...`, `x && beacon
// share --current`).
var beaconShareCommand = regexp.MustCompile(`(^|[\s/;&|(` + "`" + `'"])beacon(\.exe)?\s+share(\s|$|[;&|)'"])`)

func isBeaconShareCommand(command string) bool {
	return command != "" && beaconShareCommand.MatchString(command)
}

// counts reports whether event is activity that makes a share stale, and updates the state.
func (s *shareActivity) counts(event schema.Event) bool {
	action := event.Event.Action
	if action == "session.shared" {
		s.QuietSinceShare = true
		return false
	}
	if shareBookkeeping(action) {
		return false
	}
	callID := asymptoteobserve.ToolCallID(&event)
	promptID := asymptoteobserve.PromptID(&event)
	if isShareCallEvent(event) {
		if callID != "" {
			if s.ShareCalls == nil {
				s.ShareCalls = map[string]bool{}
			}
			s.ShareCalls[callID] = true
		}
		if promptID != "" {
			if s.SharePrompts == nil {
				s.SharePrompts = map[string]bool{}
			}
			s.SharePrompts[promptID] = true
		}
		return false
	}
	if callID != "" && s.ShareCalls[callID] {
		return false // the share call's completion, which may not repeat the command
	}
	if isAssistantOutput(event) {
		if s.QuietSinceShare || (promptID != "" && s.SharePrompts[promptID]) {
			return false
		}
		return true
	}
	s.QuietSinceShare = false
	return true
}

func isShareCallEvent(event schema.Event) bool {
	if event.Command != nil && isBeaconShareCommand(event.Command.Command) {
		return true
	}
	return event.Tool != nil && isBeaconShareCommand(event.Tool.Command)
}

// isAssistantOutput is an event that only carries the agent's own output or what it cost: no
// prompt, tool call, command or file activity.
func isAssistantOutput(event schema.Event) bool {
	switch event.Event.Action {
	case "agent.message", "agent.reasoning", "token.usage":
		return true
	}
	if event.Command != nil || event.Tool != nil || event.File != nil || event.MCP != nil {
		return false
	}
	if event.Prompt != nil && strings.TrimSpace(event.Prompt.Text) != "" {
		return false
	}
	switch event.Event.Category {
	case "prompt", "tool", "command", "file", "mcp", "approval":
		return false
	}
	return event.GenAI != nil && event.GenAI.Usage != nil
}
