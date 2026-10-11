package cmd

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// The security property behind sending Devin CLI's PermissionRequest down the default path.
//
// Devin reads `{"decision":"approve"}` from a PermissionRequest hook as the operator's yes, so a
// telemetry hook that printed it would grant every permission Devin was about to ask a person
// for -- including for the command below -- on a runtime where Beacon was installed only to watch.
// The empty object carries no decision and leaves Devin's own prompt in charge. Both platform
// spellings the installer writes are covered, because isDevinLikePlatform routes them together.
func TestDevinPermissionRequestDoesNotApproveOnBehalfOfTheUser(t *testing.T) {
	for _, platform := range []string{"devin", "devin-cli"} {
		t.Run(platform, func(t *testing.T) {
			setupHookConfigDirs(t)
			platformFlag = platform
			logPath := filepath.Join(t.TempDir(), "runtime.jsonl")
			t.Setenv("BEACON_ENDPOINT_MODE", "1")
			t.Setenv("BEACON_ENDPOINT_LOG", logPath)

			out := runHookWithInput(t, runPermissionRequest, map[string]interface{}{
				"session_id":      "devin-session-1",
				"cwd":             "/tmp/devin-project",
				"hook_event_name": "PermissionRequest",
				"tool_name":       "exec",
				"tool_input":      map[string]interface{}{"command": "rm -rf ~"},
			})
			if len(out) != 0 {
				t.Fatalf("permission response = %#v, want an empty object carrying no decision", out)
			}
			if _, ok := out["decision"]; ok {
				t.Fatalf("permission response carried a decision: %#v", out)
			}

			// Observed as a request, not recorded as an approval nobody gave.
			event := lastEndpointEvent(t, logPath)
			eventFields := event["event"].(map[string]interface{})
			if action := eventFields["action"]; action != "approval.requested" {
				t.Fatalf("event.action = %q, want approval.requested", action)
			}
			approval := event["approval"].(map[string]interface{})
			if approval["decision"] != "requested" {
				t.Fatalf("approval = %#v, want decision=requested", approval)
			}
			if got := event["command"].(map[string]interface{})["command"]; got != "rm -rf ~" {
				t.Fatalf("command = %q, want the requested command recorded", got)
			}
		})
	}
}

// A payload Beacon cannot parse is no grounds for answering on the operator's behalf either. Before
// this was fixed, unreadable stdin was the one input on which Devin got an unconditional approve.
func TestDevinPermissionRequestDoesNotApproveMalformedInput(t *testing.T) {
	for _, platform := range []string{"devin", "devin-cli"} {
		t.Run(platform, func(t *testing.T) {
			setupHookConfigDirs(t)
			platformFlag = platform
			logPath := filepath.Join(t.TempDir(), "runtime.jsonl")
			t.Setenv("BEACON_ENDPOINT_MODE", "1")
			t.Setenv("BEACON_ENDPOINT_LOG", logPath)

			out := runPermissionRequestWithRawStdin(t, []byte(`{"tool_name": "exec", "tool_input": `))
			if len(bytes.TrimSpace(out)) != 0 {
				var decoded map[string]interface{}
				if err := json.Unmarshal(out, &decoded); err != nil {
					t.Fatalf("permission response %q is not JSON: %v", out, err)
				}
				if len(decoded) != 0 {
					t.Fatalf("permission response = %#v, want an empty object carrying no decision", decoded)
				}
			}

			// Nothing parsed, so nothing is recorded -- and certainly not an approval.
			if data, err := os.ReadFile(logPath); err == nil && len(bytes.TrimSpace(data)) != 0 {
				for _, event := range endpointEvents(t, logPath) {
					if action := event["event"].(map[string]interface{})["action"]; action == "approval.allowed" {
						t.Fatalf("malformed input was logged as approval.allowed: %#v", event)
					}
				}
			}
		})
	}
}

// runPermissionRequestWithRawStdin feeds bytes that are not a JSON object, which runHookWithInput
// cannot express because it encodes its input. The payloads here are small, so writing before the
// hook runs fits in any pipe buffer.
func runPermissionRequestWithRawStdin(t *testing.T, stdin []byte) []byte {
	t.Helper()
	stdinR, stdinW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	origStdin, origStdout := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = stdinR, stdoutW
	defer func() {
		os.Stdin, os.Stdout = origStdin, origStdout
		_ = stdinR.Close()
		_ = stdoutR.Close()
	}()

	if _, err := stdinW.Write(stdin); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := stdinW.Close(); err != nil {
		t.Fatalf("close stdin writer: %v", err)
	}
	done := make(chan []byte, 1)
	go func() {
		data, _ := io.ReadAll(stdoutR)
		done <- data
	}()

	runPermissionRequest(nil, nil)

	if err := stdoutW.Close(); err != nil {
		t.Fatalf("close stdout writer: %v", err)
	}
	return <-done
}
