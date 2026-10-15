package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	observe "github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve/threatrules"
)

// LoadRules compiles every rule under dir, the same corpus `beacon scan --rules <dir>`
// runs. A rule that fails to load is an error: a scenario verified against a partial
// corpus would claim detections the shipped rules do not make.
func LoadRules(dir string) ([]*threatrules.CompiledRule, error) {
	rules, err := threatrules.LoadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("load rules from %s: %w", dir, err)
	}
	compiled := make([]*threatrules.CompiledRule, 0, len(rules))
	for _, rule := range rules {
		c, err := threatrules.Compile(rule)
		if err != nil {
			return nil, fmt.Errorf("compile rule %s: %w", rule.ID, err)
		}
		compiled = append(compiled, c)
	}
	return compiled, nil
}

// Detect runs the rules over the scenario's events and returns the findings, most
// severe first.
func Detect(rules []*threatrules.CompiledRule, events []observe.Event) ([]threatrules.Finding, error) {
	findings, err := threatrules.ScanEvents(rules, events)
	if err != nil {
		return nil, err
	}
	threatrules.SortFindings(findings)
	return findings, nil
}

// Verify checks the findings against the scenario's expect block.
func Verify(s *Scenario, rules []*threatrules.CompiledRule, findings []threatrules.Finding) error {
	known := map[string]bool{}
	for _, r := range rules {
		known[r.Rule().ID] = true
	}
	fired := map[string]bool{}
	for _, f := range findings {
		fired[f.RuleID] = true
	}
	var problems []string
	for _, id := range s.Expect.Rules {
		switch {
		case !known[id]:
			problems = append(problems, fmt.Sprintf("expected rule %q is not in the corpus", id))
		case !fired[id]:
			problems = append(problems, fmt.Sprintf("expected rule %q did not fire", id))
		}
	}
	if !s.Expect.AllowOther {
		expected := map[string]bool{}
		for _, id := range s.Expect.Rules {
			expected[id] = true
		}
		var extra []string
		for id := range fired {
			if !expected[id] {
				extra = append(extra, id)
			}
		}
		sort.Strings(extra)
		for _, id := range extra {
			problems = append(problems, fmt.Sprintf("rule %q fired but is not in expect.rules (list it, or set allow_other)", id))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s:\n  %s", s.ID, strings.Join(problems, "\n  "))
	}
	return nil
}

// Annotate returns events with one policy.detected event per finding, placed just after
// the finding's last evidence event: the moment the rule would have fired at runtime.
// The shared trace renders these as policy lines naming the rule, its severity and
// reason. They are marked inferred, because Beacon derived them; the scenario's own
// events are what the simulated runtime "observed".
func Annotate(events []observe.Event, findings []threatrules.Finding) []observe.Event {
	out := append([]observe.Event(nil), events...)
	for _, f := range findings {
		last, ok := lastEvidence(f.Events)
		if !ok {
			continue
		}
		at, _ := observe.ParseTimestamp(last.Timestamp)
		d := last
		d.Timestamp = observe.FormatTimestamp(at.Add(time.Millisecond))
		d.Event = observe.EventInfo{
			Kind:     "agent_runtime",
			Action:   "policy.detected",
			Category: "policy",
			Fidelity: observe.FidelityInferred,
		}
		d.Severity = f.Severity
		d.Message = fmt.Sprintf("Beacon threat rule %s (%s): %s", f.RuleID, f.Severity, f.Reason)
		d.Policy = &observe.PolicyInfo{
			ID:          f.RuleID,
			Name:        f.Title,
			Decision:    "detected",
			Enforcement: string(f.Posture),
			Reason:      fmt.Sprintf("[%s] %s: %s", strings.ToUpper(string(f.Severity)), f.RuleID, f.Reason),
		}
		// Keep only what ties the detection to the evidence: the call it fired on.
		var callID string
		if last.GenAI != nil && last.GenAI.Tool != nil && last.GenAI.Tool.Call != nil {
			callID = last.GenAI.Tool.Call.ID
		}
		d.GenAI = nil
		if callID != "" {
			d.GenAI = &observe.GenAIInfo{Tool: &observe.GenAIToolInfo{Call: &observe.GenAIToolCallInfo{ID: callID}}}
		}
		// A detection carries no tool, file or command fields of its own, so the trace
		// projects it as a policy line rather than as another command or file event.
		d.Tool, d.File, d.MCP, d.Command, d.Content, d.Approval = nil, nil, nil, nil, nil, nil
		if d.Prompt != nil {
			d.Prompt = &observe.PromptInfo{ID: d.Prompt.ID}
		}
		d.Raw = map[string]interface{}{"threat_rule": map[string]interface{}{
			"id": f.RuleID, "severity": string(f.Severity), "posture": string(f.Posture), "evidence_events": len(f.Events),
		}}
		out = append(out, d)
	}
	return out
}

func lastEvidence(events []observe.Event) (observe.Event, bool) {
	var best observe.Event
	var bestAt time.Time
	found := false
	for _, e := range events {
		at, err := observe.ParseTimestamp(e.Timestamp)
		if err != nil {
			continue
		}
		if !found || at.After(bestAt) {
			best, bestAt, found = e, at, true
		}
	}
	return best, found
}
