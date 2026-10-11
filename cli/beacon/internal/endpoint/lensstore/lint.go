package lensstore

import (
	"regexp"
	"strings"

	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// Lint severities. An error means the dashboard will not run the lens; a warning means the lens
// will run but something in it cannot work in the sandbox or breaks a rule in the spec.
const (
	LintError   = "error"
	LintWarning = "warning"
)

// LintFinding is one problem in a lens file. Line is 1-based, or 0 for the file as a whole.
type LintFinding struct {
	Line     int    `json:"line,omitempty"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// lintChecks are line-level patterns for things the spec forbids or the sandbox blocks. They are
// heuristics over the source text, which is what an agent writing a lens needs to hear about
// before it opens a browser; the sandbox is what actually enforces them.
var lintChecks = []struct {
	pattern *regexp.Regexp
	message string
}{
	{regexp.MustCompile(`\.(innerHTML|outerHTML)\s*[+]?=|insertAdjacentHTML\s*\(`),
		"parses a string as HTML; trace content is untrusted, so build nodes with textContent"},
	{regexp.MustCompile(`document\.write(ln)?\s*\(`),
		"uses document.write, which the lens frame refuses; build nodes with textContent"},
	{regexp.MustCompile(`\beval\s*\(|\bnew\s+Function\s*\(|setTimeout\s*\(\s*["'` + "`" + `]`),
		"evaluates a string as code, which the lens CSP blocks"},
	{regexp.MustCompile(`\bfetch\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\b|\bnew\s+EventSource\b|\bsendBeacon\s*\(`),
		"makes a network request, which the lens CSP blocks (connect-src 'none'); everything comes from getTrace()"},
	{regexp.MustCompile(`\b(src|href|action|poster)\s*=\s*["']?\s*(https?:)?//`),
		"loads a resource by URL, which the lens CSP blocks; inline it or use a data: URI"},
	{regexp.MustCompile(`url\(\s*["']?\s*(https?:)?//|@import\b`),
		"loads a stylesheet resource by URL, which the lens CSP blocks"},
	{regexp.MustCompile(`\b(localStorage|sessionStorage|indexedDB)\b|document\.cookie`),
		"uses browser storage, which an opaque-origin lens frame does not have; keep state in memory"},
	{regexp.MustCompile(`\b(window\.)?(parent|top|opener)\.(postMessage|document|location)\b|\blocation\.(href|assign|replace)\b`),
		"talks to or navigates a window; the host ignores window messages and closes a lens that navigates"},
	{regexp.MustCompile(`\b100vh\b|(^|[^-\w])height\s*:\s*100%`),
		"sizes to the viewport; the frame grows to fit the document, so a viewport-height root never settles"},
	{regexp.MustCompile(`new\s+Worker\s*\(|new\s+SharedWorker\s*\(|serviceWorker`),
		"starts a worker, which the lens CSP blocks"},
	{regexp.MustCompile(`\b(webkit)?RTC(PeerConnection|DataChannel)\b`),
		"uses WebRTC, which the lens frame removes; everything comes from getTrace()"},
	{regexp.MustCompile(`(?i)<\s*(iframe|frame|frameset|object|embed|portal|fencedframe)\b|createElement(NS)?\s*\([^)]*["'](\w+:)?(iframe|frame|object|embed|portal|fencedframe)["']|\bsrcdoc\b`),
		"creates a nested frame, which the lens frame refuses; a frame is a fresh page outside the lens's hardening"},
	{regexp.MustCompile(`(?i)<\s*link\b|createElement(NS)?\s*\([^)]*["'](\w+:)?link["']|\b(preconnect|prefetch|prerender|dns-prefetch|modulepreload)\b`),
		"adds a <link> or resource hint, which the lens frame refuses: a lens loads nothing by URL, and hints like preconnect can start requests the CSP does not see"},
	{regexp.MustCompile(`(?i)\bspeculationrules\b`),
		"adds speculation rules, which the lens frame refuses: they can start requests the CSP does not see"},
	{regexp.MustCompile(`(?i)\bshadowrootmode\b`),
		"declares a shadow root in markup; keep the lens in its own document, where the lens frame's hardening can see it"},
}

// Lint checks a lens file against spec/lenses/SPEC.md. The file-level rules (size, manifest) are
// errors; everything else is a warning tied to the line it appears on.
func Lint(html []byte) []LintFinding {
	var findings []LintFinding
	if _, err := asymptoteobserve.CheckLensFile(html); err != nil {
		for _, line := range strings.Split(err.Error(), "\n") {
			findings = append(findings, LintFinding{Severity: LintError, Message: line})
		}
	}
	text := strings.ReplaceAll(string(html), "\r\n", "\n")
	for i, line := range strings.Split(text, "\n") {
		for _, check := range lintChecks {
			if check.pattern.MatchString(line) {
				findings = append(findings, LintFinding{Line: i + 1, Severity: LintWarning, Message: check.message})
			}
		}
	}
	if !strings.Contains(text, "window.beacon.getTrace()") && !strings.Contains(text, "beacon.getTrace()") {
		findings = append(findings, LintFinding{Severity: LintWarning, Message: "never calls window.beacon.getTrace(), so it has no trace to render and the dashboard will give up on it after 10 seconds"})
	}
	return findings
}

// HasLintErrors reports whether any finding is an error.
func HasLintErrors(findings []LintFinding) bool {
	for _, f := range findings {
		if f.Severity == LintError {
			return true
		}
	}
	return false
}
