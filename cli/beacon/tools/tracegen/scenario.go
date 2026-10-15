package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve/threatrules"
	"gopkg.in/yaml.v3"
)

// Scenario is one simulated agent session that reproduces a vulnerability. It is
// authored as YAML under scenarios/ and turned into Beacon endpoint events by Build.
type Scenario struct {
	ID      string `yaml:"id"`
	Title   string `yaml:"title"`
	Summary string `yaml:"summary"`
	// Vulnerability describes what the session reproduces, for the README table and
	// for whoever reviews the trace before it is published.
	Vulnerability Vulnerability `yaml:"vulnerability"`
	// Harness is the normalized runtime name the trace is attributed to (claude_code,
	// codex_cli, cursor, ...). Model is the model the agent turns name.
	Harness string `yaml:"harness"`
	Model   string `yaml:"model"`
	// Project is the directory name the session runs in. Paths under it are written
	// relative to it in the shared trace.
	Project string `yaml:"project"`
	// Start is the timestamp of the first event; zero means defaultStart.
	Start time.Time `yaml:"start"`
	// Expect lists the rules that must fire. Verify fails when one does not, so a
	// scenario cannot drift away from the detection it exists to showcase.
	Expect Expect `yaml:"expect"`
	Steps  []Step `yaml:"steps"`

	path string
}

// Vulnerability is the class of flaw a scenario reproduces.
type Vulnerability struct {
	Class      string   `yaml:"class"`
	OWASPLLM   string   `yaml:"owasp_llm,omitempty"`
	MitreAtlas string   `yaml:"mitre_atlas,omitempty"`
	References []string `yaml:"references,omitempty"`
}

// Expect is what Verify checks against the rule corpus.
type Expect struct {
	// Rules must each produce at least one finding.
	Rules []string `yaml:"rules"`
	// AllowOther, when false (the default), also fails Verify when a rule outside
	// Rules fires, so an unexpected finding is noticed and either listed or fixed.
	AllowOther bool `yaml:"allow_other,omitempty"`
}

// Step is one thing that happens in the session. Exactly one kind is set.
type Step struct {
	// After is the delay since the previous step ("3s", "1m"); empty means defaultGap.
	After string `yaml:"after,omitempty"`

	Prompt   string        `yaml:"prompt,omitempty"`
	Agent    string        `yaml:"agent,omitempty"`
	Thinking string        `yaml:"thinking,omitempty"`
	Read     *ReadStep     `yaml:"read,omitempty"`
	Fetch    *FetchStep    `yaml:"fetch,omitempty"`
	Command  *CommandStep  `yaml:"command,omitempty"`
	Edit     *EditStep     `yaml:"edit,omitempty"`
	MCP      *MCPStep      `yaml:"mcp,omitempty"`
	Approval *ApprovalStep `yaml:"approval,omitempty"`
	// Event is an escape hatch: a raw Beacon event in the same YAML shape rule
	// fixtures use. Build fills in the envelope (timestamp, session, harness).
	Event *threatrules.FixtureEvent `yaml:"event,omitempty"`
}

// ReadStep is the agent reading a file; Content is what the read returned.
type ReadStep struct {
	Path    string `yaml:"path"`
	Content string `yaml:"content,omitempty"`
}

// FetchStep is the agent fetching a URL; Content is the page it got back.
type FetchStep struct {
	URL     string `yaml:"url"`
	Content string `yaml:"content,omitempty"`
}

// CommandStep is a shell command the agent ran.
type CommandStep struct {
	Command     string `yaml:"command"`
	Description string `yaml:"description,omitempty"`
	Output      string `yaml:"output,omitempty"`
	ExitCode    *int   `yaml:"exit_code,omitempty"`
}

// EditStep is the agent writing a file; Diff is a unified diff of the change.
type EditStep struct {
	Path string `yaml:"path"`
	Diff string `yaml:"diff,omitempty"`
}

// MCPStep is a call to an MCP server's tool.
type MCPStep struct {
	Server      string         `yaml:"server"`
	Tool        string         `yaml:"tool"`
	Description string         `yaml:"description,omitempty"`
	Arguments   map[string]any `yaml:"arguments,omitempty"`
	Result      string         `yaml:"result,omitempty"`
}

// ApprovalStep is the operator's decision on a tool call the runtime asked about.
type ApprovalStep struct {
	Decision string `yaml:"decision"` // allowed or denied
	Reason   string `yaml:"reason,omitempty"`
	Command  string `yaml:"command,omitempty"`
}

var (
	defaultStart = time.Date(2026, 9, 1, 15, 0, 0, 0, time.UTC)
	defaultGap   = 4 * time.Second
	scenarioID   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,79}$`)
)

func (s Step) kind() (string, int) {
	kinds := map[string]bool{
		"prompt": s.Prompt != "", "agent": s.Agent != "", "thinking": s.Thinking != "",
		"read": s.Read != nil, "fetch": s.Fetch != nil, "command": s.Command != nil,
		"edit": s.Edit != nil, "mcp": s.MCP != nil, "approval": s.Approval != nil,
		"event": s.Event != nil,
	}
	var set []string
	for name, ok := range kinds {
		if ok {
			set = append(set, name)
		}
	}
	sort.Strings(set)
	return strings.Join(set, ","), len(set)
}

// LoadScenario reads and validates one scenario file. Unknown keys are refused so a
// typo does not silently drop a step.
func LoadScenario(path string) (*Scenario, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var s Scenario
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	s.path = path
	if err := s.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// LoadScenarios reads every *.yaml under dir, sorted by id.
func LoadScenarios(dir string) ([]*Scenario, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, err
	}
	var out []*Scenario
	seen := map[string]string{}
	for _, path := range paths {
		s, err := LoadScenario(path)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[s.ID]; dup {
			return nil, fmt.Errorf("scenario id %q is used by %s and %s", s.ID, prev, path)
		}
		seen[s.ID] = path
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Scenario) validate() error {
	var errs []error
	if !scenarioID.MatchString(s.ID) {
		errs = append(errs, fmt.Errorf("id %q must be 3-80 lowercase letters, digits and dashes", s.ID))
	}
	if base := strings.TrimSuffix(filepath.Base(s.path), ".yaml"); s.path != "" && base != s.ID {
		errs = append(errs, fmt.Errorf("file name %q must match id %q", base, s.ID))
	}
	if strings.TrimSpace(s.Title) == "" {
		errs = append(errs, errors.New("title is required"))
	}
	if strings.TrimSpace(s.Vulnerability.Class) == "" {
		errs = append(errs, errors.New("vulnerability.class is required"))
	}
	if s.Harness == "" {
		errs = append(errs, errors.New("harness is required"))
	}
	if s.Project == "" || strings.ContainsAny(s.Project, `/\`) {
		errs = append(errs, errors.New("project is required and must be a single directory name"))
	}
	if len(s.Expect.Rules) == 0 {
		errs = append(errs, errors.New("expect.rules must name at least one rule the scenario showcases"))
	}
	if len(s.Steps) == 0 || s.Steps[0].Prompt == "" {
		errs = append(errs, errors.New("steps must start with a prompt"))
	}
	for i, step := range s.Steps {
		if kind, n := step.kind(); n != 1 {
			errs = append(errs, fmt.Errorf("step %d must set exactly one kind, has %d (%s)", i+1, n, kind))
		}
		if step.After != "" {
			if d, err := time.ParseDuration(step.After); err != nil || d < 0 {
				errs = append(errs, fmt.Errorf("step %d: after %q is not a non-negative duration", i+1, step.After))
			}
		}
		if step.Approval != nil && step.Approval.Decision != "allowed" && step.Approval.Decision != "denied" {
			errs = append(errs, fmt.Errorf("step %d: approval.decision must be allowed or denied", i+1))
		}
	}
	return errors.Join(errs...)
}
