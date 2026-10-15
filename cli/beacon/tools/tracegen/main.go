// Command tracegen generates simulated agent sessions that reproduce security
// vulnerabilities, verifies that Beacon's open threat rules catch each one, and
// publishes them to beacon.sh as shared traces with the detections inline.
//
// It is a maintainer tool, not part of the shipped CLI. See README.md.
//
//	go run ./tools/tracegen list
//	go run ./tools/tracegen verify
//	go run ./tools/tracegen build   -out /tmp/tracegen [-only id,...]
//	go run ./tools/tracegen publish [-only id,...] [-visibility direct|public|private] [-dry-run]
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	observe "github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve/threatrules"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "tracegen:", err)
		os.Exit(1)
	}
}

const usage = `usage: tracegen <command> [flags]

commands:
  list      show every scenario, its vulnerability class and the rules it expects
  verify    build every scenario and check its expected rules fire (and no others)
  build     write each scenario's runtime JSONL, findings and share payload to -out
  publish   verify, then upload each scenario to beacon.sh as a shared trace

common flags:
  -scenarios dir   scenario directory (default: tools/tracegen/scenarios)
  -rules dir       rule corpus (default: the repository's rules/)
  -only ids        comma-separated scenario ids to limit to
`

type common struct {
	scenarios, rules, only string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.scenarios, "scenarios", "", "scenario directory")
	fs.StringVar(&c.rules, "rules", "", "rule corpus directory")
	fs.StringVar(&c.only, "only", "", "comma-separated scenario ids")
}

// load resolves the default paths against the repository root and returns the selected
// scenarios and the compiled corpus.
func (c *common) load() ([]*Scenario, []*threatrules.CompiledRule, error) {
	if c.scenarios == "" || c.rules == "" {
		root, err := repoRoot()
		if err != nil {
			return nil, nil, err
		}
		if c.scenarios == "" {
			c.scenarios = filepath.Join(root, "cli", "beacon", "tools", "tracegen", "scenarios")
		}
		if c.rules == "" {
			c.rules = filepath.Join(root, "rules")
		}
	}
	all, err := LoadScenarios(c.scenarios)
	if err != nil {
		return nil, nil, err
	}
	scenarios := all
	if c.only != "" {
		want := map[string]bool{}
		for _, id := range strings.Split(c.only, ",") {
			if id = strings.TrimSpace(id); id != "" {
				want[id] = true
			}
		}
		scenarios = nil
		for _, s := range all {
			if want[s.ID] {
				scenarios = append(scenarios, s)
				delete(want, s.ID)
			}
		}
		for id := range want {
			return nil, nil, fmt.Errorf("no scenario %q in %s", id, c.scenarios)
		}
	}
	rules, err := LoadRules(c.rules)
	if err != nil {
		return nil, nil, err
	}
	return scenarios, rules, nil
}

// repoRoot walks up from the working directory to the agent-beacon checkout.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if isDir(filepath.Join(dir, "rules")) && isDir(filepath.Join(dir, "spec", "threat-rules")) {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("not inside an agent-beacon checkout: pass -scenarios and -rules")
		}
		dir = parent
	}
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

// Generated is one scenario carried through the whole pipeline.
type Generated struct {
	Scenario *Scenario
	Events   []observe.Event // annotated: scenario events plus policy.detected
	Findings []threatrules.Finding
	Err      error // Verify's verdict
}

func generate(s *Scenario, rules []*threatrules.CompiledRule) (Generated, error) {
	events, err := Build(s)
	if err != nil {
		return Generated{}, err
	}
	findings, err := Detect(rules, events)
	if err != nil {
		return Generated{}, fmt.Errorf("%s: scan: %w", s.ID, err)
	}
	return Generated{
		Scenario: s,
		Events:   Annotate(events, findings),
		Findings: findings,
		Err:      Verify(s, rules, findings),
	}, nil
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return nil
	}
	cmd, rest := args[0], args[1:]
	fs := flag.NewFlagSet("tracegen "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs)
	switch cmd {
	case "list":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return cmdList(&c, stdout)
	case "verify":
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return cmdVerify(&c, stdout)
	case "build":
		out := fs.String("out", "", "output directory (required)")
		prefix := fs.String("title-prefix", defaultTitlePrefix, "prefix for every published title")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if *out == "" {
			return errors.New("build: -out is required")
		}
		return cmdBuild(&c, *out, *prefix, stdout)
	case "publish":
		opts := publishFlags{}
		fs.StringVar(&opts.visibility, "visibility", observe.ShareVisibilityDirect, "direct (link only), public (listed on Discover) or private")
		fs.BoolVar(&opts.forceVisibility, "force-visibility", false, "apply -visibility to traces that already exist")
		fs.BoolVar(&opts.yes, "yes", false, "confirm publishing publicly")
		fs.BoolVar(&opts.dryRun, "dry-run", false, "print the payloads instead of uploading")
		fs.StringVar(&opts.key, "key", "", "bcn_api_ key (default: beacon login, then BEACON_API_KEY)")
		fs.StringVar(&opts.baseURL, "base-url", "", "Beacon service URL (default: https://beacon.sh)")
		fs.StringVar(&opts.titlePrefix, "title-prefix", defaultTitlePrefix, "prefix for every published title")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		return cmdPublish(&c, opts, stdout, stderr)
	}
	return fmt.Errorf("unknown command %q\n\n%s", cmd, usage)
}

// defaultTitlePrefix keeps a generated trace from being mistaken for a captured one on
// Discover, which describes its feed as real community sessions.
const defaultTitlePrefix = "Simulated: "

func cmdList(c *common, stdout io.Writer) error {
	scenarios, _, err := c.load()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tHARNESS\tCLASS\tEXPECTED RULES")
	for _, s := range scenarios {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.ID, s.Harness, s.Vulnerability.Class, strings.Join(s.Expect.Rules, ", "))
	}
	return w.Flush()
}

func cmdVerify(c *common, stdout io.Writer) error {
	scenarios, rules, err := c.load()
	if err != nil {
		return err
	}
	var failed []error
	for _, s := range scenarios {
		g, err := generate(s, rules)
		if err != nil {
			return err
		}
		status := "ok  "
		if g.Err != nil {
			status = "FAIL"
			failed = append(failed, g.Err)
		}
		fmt.Fprintf(stdout, "%s %-48s %d findings: %s\n", status, s.ID, len(g.Findings), findingIDs(g.Findings))
	}
	if len(failed) > 0 {
		return fmt.Errorf("%d of %d scenarios failed:\n%w", len(failed), len(scenarios), errors.Join(failed...))
	}
	fmt.Fprintf(stdout, "%d scenarios verified against %d rules\n", len(scenarios), len(rules))
	return nil
}

func findingIDs(findings []threatrules.Finding) string {
	seen := map[string]bool{}
	var ids []string
	for _, f := range findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ids = append(ids, f.RuleID)
		}
	}
	return strings.Join(ids, ", ")
}

// cmdBuild writes, per scenario, <id>/runtime.jsonl (the annotated endpoint events, which
// `beacon scan` and the local dashboard can read), <id>/findings.json, and
// <id>/payload.json (exactly what publish would send).
func cmdBuild(c *common, out, prefix string, stdout io.Writer) error {
	scenarios, rules, err := c.load()
	if err != nil {
		return err
	}
	for _, s := range scenarios {
		g, err := generate(s, rules)
		if err != nil {
			return err
		}
		if g.Err != nil {
			return g.Err
		}
		dir := filepath.Join(out, s.ID)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		var jsonl strings.Builder
		for _, e := range g.Events {
			line, err := json.Marshal(e)
			if err != nil {
				return err
			}
			jsonl.Write(line)
			jsonl.WriteByte('\n')
		}
		if err := os.WriteFile(filepath.Join(dir, "runtime.jsonl"), []byte(jsonl.String()), 0o644); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, "findings.json"), summarizeFindings(g.Findings)); err != nil {
			return err
		}
		payload := BuildPayload(s, g.Events, PayloadOptions{Visibility: observe.ShareVisibilityDirect, TitlePrefix: prefix})
		if err := writeJSON(filepath.Join(dir, "payload.json"), payload); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s: %d events, %d findings -> %s\n", s.ID, len(payload.Events), len(g.Findings), dir)
	}
	return nil
}

type findingSummary struct {
	RuleID   string   `json:"rule_id"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	Reason   string   `json:"reason"`
	Evidence []string `json:"evidence"` // "<timestamp> <action>"
}

func summarizeFindings(findings []threatrules.Finding) []findingSummary {
	out := make([]findingSummary, 0, len(findings))
	for _, f := range findings {
		fs := findingSummary{RuleID: f.RuleID, Title: f.Title, Severity: string(f.Severity), Reason: f.Reason}
		for _, e := range f.Events {
			fs.Evidence = append(fs.Evidence, e.Timestamp+" "+e.Event.Action)
		}
		out = append(out, fs)
	}
	return out
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

type publishFlags struct {
	visibility, key, baseURL, titlePrefix string
	forceVisibility, yes, dryRun          bool
}

func cmdPublish(c *common, opts publishFlags, stdout, stderr io.Writer) error {
	if !observe.ValidShareVisibility(opts.visibility) {
		return fmt.Errorf("publish: -visibility must be direct, public or private")
	}
	if opts.visibility == observe.ShareVisibilityPublic && !opts.yes && !opts.dryRun {
		return errors.New("publish: public traces are listed on Discover; review them as direct links first, then pass -yes")
	}
	scenarios, rules, err := c.load()
	if err != nil {
		return err
	}
	var generated []Generated
	for _, s := range scenarios {
		g, err := generate(s, rules)
		if err != nil {
			return err
		}
		if g.Err != nil {
			// Never publish a scenario whose detections do not hold against the corpus.
			return fmt.Errorf("publish: refusing, verification failed:\n%w", g.Err)
		}
		generated = append(generated, g)
	}
	payloadOpts := PayloadOptions{Visibility: opts.visibility, TitlePrefix: opts.titlePrefix}
	if opts.dryRun {
		var payloads []Payload
		for _, g := range generated {
			payloads = append(payloads, BuildPayload(g.Scenario, g.Events, payloadOpts))
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(payloads)
	}
	client, err := NewClient(opts.key, opts.baseURL, os.Getenv)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var results []PublishResult
	for _, g := range generated {
		res, err := Publish(ctx, client, BuildPayload(g.Scenario, g.Events, payloadOpts), opts.forceVisibility)
		if err != nil {
			return fmt.Errorf("%s: %w", g.Scenario.ID, err)
		}
		res.ScenarioID = g.Scenario.ID
		results = append(results, res)
		fmt.Fprintf(stderr, "%s -> %s (%s, %d events)\n", res.ScenarioID, res.URL, res.Visibility, res.Events)
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}
