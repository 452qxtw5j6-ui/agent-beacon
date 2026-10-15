package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"strings"
	"time"

	observe "github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// Synthetic sessions run in a fixed, fake home so the share scrubber rewrites their
// paths the same way on every machine and nothing of the generating machine leaks.
const (
	syntheticHome     = "/home/dev"
	syntheticHostname = "tracegen"
	// ProvenanceSource marks every published trace as generated rather than captured.
	ProvenanceSource = "beacon-tracegen"
)

// SessionID is the scenario's stable session id: a UUID-shaped hash of its id, so a
// re-publish upserts the same shared trace instead of creating a second one.
func (s *Scenario) SessionID() string {
	sum := sha256.Sum256([]byte("beacon-tracegen:" + s.ID))
	h := hex.EncodeToString(sum[:16])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// WorkingDirectory is where the simulated session runs.
func (s *Scenario) WorkingDirectory() string {
	return path.Join(syntheticHome, "src", s.Project)
}

// Build turns the scenario into the endpoint events a real capture would have written:
// session start, one or two events per step (a tool invocation and its completion for
// tool steps, so the shared trace pairs them by tool_call_id), and session end. It adds
// no detections; Annotate does, from the rules that actually fire.
func Build(s *Scenario) ([]observe.Event, error) {
	b := builder{s: s, at: s.Start}
	if b.at.IsZero() {
		b.at = defaultStart
	}
	b.emit(b.event("session.started", "session", "Session started"))
	b.at = b.at.Add(time.Second)
	for i, step := range s.Steps {
		gap := defaultGap
		if step.After != "" {
			gap, _ = time.ParseDuration(step.After)
		}
		if i > 0 {
			b.at = b.at.Add(gap)
		}
		if err := b.step(i, step); err != nil {
			return nil, fmt.Errorf("%s step %d: %w", s.ID, i+1, err)
		}
	}
	b.at = b.at.Add(defaultGap)
	b.emit(b.event("session.ended", "session", "Session ended"))
	return b.events, nil
}

type builder struct {
	s      *Scenario
	at     time.Time
	calls  int
	prompt string
	events []observe.Event
}

func (b *builder) emit(e observe.Event) { b.events = append(b.events, e) }

func (b *builder) event(action, category, message string) observe.Event {
	e := observe.Event{
		Timestamp:     observe.FormatTimestamp(b.at),
		Vendor:        observe.Vendor,
		Product:       observe.Product,
		SchemaVersion: observe.SchemaVersion,
		Event: observe.EventInfo{
			Kind:     "agent_runtime",
			Action:   action,
			Category: category,
			Fidelity: observe.FidelityObserved,
		},
		Severity: observe.SeverityInfo,
		Endpoint: observe.EndpointInfo{Hostname: syntheticHostname, OS: "linux"},
		Harness: observe.HarnessInfo{
			Name:             b.s.Harness,
			CollectionMethod: observe.CollectionMethodHook,
		},
		Session: &observe.SessionInfo{ID: b.s.SessionID(), WorkingDirectory: b.s.WorkingDirectory()},
		Model:   b.s.Model,
		Message: message,
	}
	if b.prompt != "" {
		e.Prompt = &observe.PromptInfo{ID: b.prompt}
	}
	return e
}

func (b *builder) callID() string {
	b.calls++
	return fmt.Sprintf("toolu_tg_%s_%02d", strings.ReplaceAll(b.s.SessionID()[:8], "-", ""), b.calls)
}

func retained() *observe.ContentInfo {
	return &observe.ContentInfo{Retention: observe.ContentRetentionFull, Included: true}
}

// invoke emits the pre-tool event for a call and advances the clock a little, so the
// completion lands after it as a post-tool hook's would.
func (b *builder) invoke(id, tool string, args map[string]any) {
	e := b.event("tool.invoked", "tool", tool+" invoked")
	e.Tool = &observe.ToolInfo{Name: tool}
	e.GenAI = &observe.GenAIInfo{Tool: &observe.GenAIToolInfo{Name: tool, Call: &observe.GenAIToolCallInfo{ID: id, Arguments: args}}}
	b.emit(e)
	b.at = b.at.Add(700 * time.Millisecond)
}

func toolCall(tool, id string, args map[string]any, result any) *observe.GenAIInfo {
	return &observe.GenAIInfo{Tool: &observe.GenAIToolInfo{Name: tool, Call: &observe.GenAIToolCallInfo{ID: id, Arguments: args, Result: result}}}
}

func (b *builder) absPath(p string) string {
	if path.IsAbs(p) || strings.HasPrefix(p, "~") {
		return strings.Replace(p, "~", syntheticHome, 1)
	}
	return path.Join(b.s.WorkingDirectory(), p)
}

func (b *builder) step(i int, step Step) error {
	switch {
	case step.Prompt != "":
		b.prompt = fmt.Sprintf("prompt-%s-%02d", b.s.SessionID()[:8], i+1)
		e := b.event("prompt.submitted", "prompt", "User prompt submitted")
		e.Prompt = &observe.PromptInfo{ID: b.prompt, Text: step.Prompt}
		e.Content = retained()
		b.emit(e)
	case step.Agent != "":
		e := b.event("agent.message", "agent", step.Agent)
		e.Content = retained()
		b.emit(e)
	case step.Thinking != "":
		e := b.event("agent.reasoning", "agent", step.Thinking)
		e.Content = retained()
		b.emit(e)
	case step.Read != nil:
		id, p := b.callID(), b.absPath(step.Read.Path)
		args := map[string]any{"file_path": p}
		b.invoke(id, "Read", args)
		e := b.event("file.read", "file", "File read observed")
		e.Tool = &observe.ToolInfo{Name: "Read", Path: p}
		e.File = &observe.FileInfo{Path: p, Operation: "read"}
		e.GenAI = toolCall("Read", id, args, step.Read.Content)
		e.Content = retained()
		b.emit(e)
	case step.Fetch != nil:
		id := b.callID()
		args := map[string]any{"url": step.Fetch.URL}
		b.invoke(id, "WebFetch", args)
		e := b.event("tool.completed", "tool", "Web fetch completed")
		e.Tool = &observe.ToolInfo{Name: "WebFetch", Path: step.Fetch.URL}
		e.GenAI = toolCall("WebFetch", id, args, step.Fetch.Content)
		e.Content = retained()
		b.emit(e)
	case step.Command != nil:
		id := b.callID()
		args := map[string]any{"command": step.Command.Command}
		if step.Command.Description != "" {
			args["description"] = step.Command.Description
		}
		b.invoke(id, "Bash", args)
		e := b.event("command.executed", "command", "Shell command executed")
		code := 0
		if step.Command.ExitCode != nil {
			code = *step.Command.ExitCode
		}
		e.Tool = &observe.ToolInfo{Name: "Bash", Command: step.Command.Command}
		e.Command = &observe.CommandInfo{Command: step.Command.Command, ExitCode: &code, DurationMS: 640, Output: step.Command.Output}
		e.GenAI = toolCall("Bash", id, args, nil)
		e.Content = retained()
		b.emit(e)
	case step.Edit != nil:
		id, p := b.callID(), b.absPath(step.Edit.Path)
		args := map[string]any{"file_path": p}
		b.invoke(id, "Edit", args)
		e := b.event("file.modified", "file", "File edit observed")
		e.Tool = &observe.ToolInfo{Name: "Edit", Path: p}
		e.File = &observe.FileInfo{Path: p, Operation: "edit", Diff: step.Edit.Diff}
		e.GenAI = toolCall("Edit", id, args, nil)
		e.Content = retained()
		b.emit(e)
	case step.MCP != nil:
		id := b.callID()
		name := "mcp__" + step.MCP.Server + "__" + step.MCP.Tool
		b.invoke(id, name, step.MCP.Arguments)
		e := b.event("mcp.tool_invoked", "mcp", "MCP tool invocation observed")
		e.Tool = &observe.ToolInfo{Name: name}
		e.MCP = &observe.MCPInfo{Server: step.MCP.Server, Tool: step.MCP.Tool}
		e.GenAI = toolCall(name, id, step.MCP.Arguments, step.MCP.Result)
		e.GenAI.Tool.Description = step.MCP.Description
		e.Content = retained()
		b.emit(e)
	case step.Approval != nil:
		e := b.event("approval."+step.Approval.Decision, "approval", "Operator "+step.Approval.Decision+" a tool call")
		e.Approval = &observe.ApprovalInfo{Required: true, Decision: step.Approval.Decision, Reason: step.Approval.Reason}
		if step.Approval.Command != "" {
			e.Tool = &observe.ToolInfo{Name: "Bash", Command: step.Approval.Command}
			e.Command = &observe.CommandInfo{Command: step.Approval.Command}
		}
		b.emit(e)
	case step.Event != nil:
		e := step.Event.Event
		base := b.event(e.Event.Action, e.Event.Category, e.Message)
		e.Timestamp, e.Vendor, e.Product, e.SchemaVersion = base.Timestamp, base.Vendor, base.Product, base.SchemaVersion
		e.Event.Kind, e.Endpoint, e.Session = base.Event.Kind, base.Endpoint, base.Session
		if e.Event.Fidelity == "" {
			e.Event.Fidelity = base.Event.Fidelity
		}
		if e.Harness.Name == "" {
			e.Harness = base.Harness
		}
		if e.Severity == "" {
			e.Severity = base.Severity
		}
		if e.Model == "" {
			e.Model = base.Model
		}
		if e.Prompt == nil {
			e.Prompt = base.Prompt
		}
		if e.Event.Action == "" {
			return fmt.Errorf("event.event.action is required")
		}
		b.emit(e)
	}
	return nil
}
