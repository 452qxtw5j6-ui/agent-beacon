package cmd

import (
	"github.com/spf13/cobra"

	"github.com/asymptote-labs/agent-beacon/cli/beacon-hooks/internal/logging"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve/policycontract"
)

var permissionRequestCmd = &cobra.Command{
	Use:   "permission-request",
	Short: "Observe permission requests for local endpoint telemetry",
	Long:  `PermissionRequest hook - triggered when an agent runtime needs a permission decision.`,
	Run:   runPermissionRequest,
}

func init() {
	rootCmd.AddCommand(permissionRequestCmd)
}

func runPermissionRequest(cmd *cobra.Command, args []string) {
	input, err := readStdinJSON()
	if err != nil {
		// No runtime gets an answer on a payload Beacon could not read, Devin CLI included. A hook
		// that cannot say what is being asked has no business answering it, and the empty object
		// leaves the runtime's own prompt in charge.
		outputJSON(emptyResponse)
		return
	}

	sessionID := resolveSessionID(input, platformFlag)
	logger := newHookLogger("permission-request", platformFlag, sessionID)

	if denial := enforcePolicy(logger, input, sessionID, policycontract.PhasePermissionRequest); denial != nil {
		denial.emit()
		return
	}

	// Devin CLI takes the default path at the bottom, for the Qwen reason in preToolResponse.
	// Devin reads `{"decision":"approve"}` from a PermissionRequest hook as the answer to the
	// question it was about to put to the operator, so a hook that printed it would not be
	// observing the request -- it would be granting it, for every tool call that needed a person's
	// yes, on a runtime where the hook was installed to watch. Devin's own documented example
	// prints a decision only for the calls it means to approve and exits with no output for the
	// rest, which is what the empty object says here: no opinion, ask the operator as usual. What
	// Beacon saw is a request, so that is what it records; Devin does not report the operator's
	// answer to a hook, and Beacon does not invent one. A policy provider's deny above is still a
	// real answer and still reaches Devin. TestDevinPermissionRequestDoesNotApproveOnBehalfOfTheUser
	// holds this in place.
	if platformFlag == "hermes" {
		emitHermesApproval(logger, input, sessionID)
		outputJSON(emptyResponse)
		return
	}
	// Kimi Code sends two events through this one subcommand -- PermissionRequest before it blocks
	// on a person and PermissionResult once they have answered -- so unlike every runtime above it
	// records an outcome and not only a question. The same shape hermes uses just above, and for
	// the same reason: the pair is one conversation, and splitting it across two subcommands would
	// mean two readers that have to agree about what a decision is.
	if platformFlag == kimiPlatform {
		emitKimiApproval(logger, input, sessionID)
		outputJSON(emptyResponse)
		return
	}

	emitPreToolDecision(logger, input, sessionID, "approval.requested", "requested", "Permission request observed", asymptoteobserve.FidelityObserved)
	outputJSON(emptyResponse)
}

func emitHermesApproval(logger *logging.Logger, input map[string]interface{}, sessionID string) {
	command := hermesFirstString(input, "command")
	description := hermesFirstString(input, "description", "reason")
	choice := hermesFirstString(input, "choice", "decision")
	hookEvent := getFirstStr(input, "hook_event_name", "hookEventName")
	if hookEvent == "" {
		hookEvent = hermesFirstString(input, "hook_event_name", "hookEventName")
	}
	decision := "requested"
	action := "approval.requested"
	message := "Permission request observed"
	if hookEvent == "post_approval_response" || choice != "" {
		decision = choice
		if decision == "" {
			decision = "unknown"
		}
		action = "approval.allowed"
		message = "Permission response observed"
		if decision == "deny" || decision == "denied" || decision == "timeout" {
			action = "approval.denied"
		} else if decision == "unknown" {
			action = "approval.requested"
		}
	}
	fields := sessionFields(sessionID, input)
	if command != "" {
		fields["command"] = map[string]interface{}{"command": command}
		fields["tool"] = mergeNested(fields["tool"], map[string]interface{}{"name": "terminal", "command": command})
	}
	fields["approval"] = map[string]interface{}{
		"required": true,
		"decision": decision,
		"reason":   description,
	}
	emitHookEvent(logger, action, "approval", "info", message, input, fields)
}
