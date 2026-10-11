package asymptoteobserve

import (
	"encoding/json"
	"regexp"
	"strings"
)

const (
	DefaultStringLimit    = 4096
	DefaultRawStringLimit = 2048
)

// redactedValue replaces a secret. Rules that match a labeled value keep the label (`token=`,
// `Authorization: Bearer `, a URL's `scheme://user:`) and replace only the value, so the text still
// says what was there.
const redactedValue = "[REDACTED]"

// secretKeyName is the part of a label that marks the value after it as a secret: `token`,
// `GITHUB_TOKEN`, `api_key`, `AWS_SECRET_ACCESS_KEY`, `"password"`. The label must end in the
// marker, so `input_tokens: 812` and `max_tokens=4096` stay readable.
const secretKeyName = `[A-Za-z0-9_.-]*?(?:api[_-]?key|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|` +
	`token|secret|password|passwd|passphrase|authorization|credentials?)`

// secretAssignment runs from the end of a label to the start of its value: an optional closing quote
// (escaped too, for JSON quoted inside a string), the separator, and an optional opening quote.
const secretAssignment = "(?:\\\\?[\"'`])?\\s*[:=]\\s*(?:\\\\?[\"'`])?"

// secretValue is the value itself, up to a quote, an escape, a separator or the end of a structure.
// It never starts with `[`, so a value already replaced with [REDACTED] is left as it is and
// redacting twice gives the same text as redacting once.
const secretValue = "[^\"'`,\\s}\\]\\\\\\[][^\"'`,\\s}\\]\\\\]*"

// secretRule is one redaction. ${1} and ${3}, when the pattern has them, are kept around the value.
type secretRule struct {
	pattern     *regexp.Regexp
	replacement string
	// keep, when set, leaves a match alone if its value (${2}) passes.
	keep func(value string) bool
}

// isAuthScheme reports whether a labeled value is an Authorization scheme rather than a
// credential. `Authorization: Bearer x` is redacted to `Authorization: Bearer [REDACTED]` by the
// header rule, and the assignment rule must not then take `Bearer` for the value and erase what
// kind of credential the line held.
func isAuthScheme(value string) bool {
	switch strings.ToLower(value) {
	case "bearer", "basic", "token", "digest":
		return true
	}
	return false
}

var secretRules = []secretRule{
	// A private key block, or the rest of the text when the block was cut before its END line.
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----|[\s\S]*$)`), redactedValue, nil},
	// An Authorization header's credential after its scheme: Bearer, Basic, Token, Digest.
	{regexp.MustCompile(`(?i)(authorization["']?\s*[:=]\s*["']?(?:bearer|basic|token|digest)\s+)([^"'\s,]+)()`), "${1}" + redactedValue, nil},
	{regexp.MustCompile(`(?i)(\bbearer\s+)([a-z0-9._~+/=-]+)()`), "${1}" + redactedValue, nil},
	// A labeled assignment in prose, shell, env files, YAML, TOML or JSON: `token=x`,
	// `export GITHUB_TOKEN="x"`, `{"api_key": "x"}`. The closing quote of a quoted label is allowed
	// between the label and the separator.
	{regexp.MustCompile(`(?i)(\b` + secretKeyName + secretAssignment + `)(` + secretValue + `)()`), "${1}" + redactedValue, isAuthScheme},
	// A command-line flag: `--password x`, `--token=x`, `--api-key x`.
	{regexp.MustCompile(`(?i)((?:^|\s)--?[a-z0-9-]*(?:password|passwd|passphrase|token|secret|api-?key|access-?key)(?:=|\s+))([^\s"'-][^\s"']*)()`), "${1}" + redactedValue, nil},
	// The password in a URL's userinfo: `postgres://user:pw@host`, `https://x-access-token:t@github.com`.
	{regexp.MustCompile(`(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@"'<>]+:)([^@/\s"'<>]+)(@)`), "${1}" + redactedValue + "${3}", nil},
	// Credentials recognizable by their own shape, wherever they appear. The type prefix is public
	// and stays (`ghp_[REDACTED]`, `AKIA[REDACTED]`), the way secret scanners report a finding: the
	// line still says a GitHub token or an AWS key was there, which is what detection rules match on
	// in the log, and none of the credential is left.
	{regexp.MustCompile(`\b(sk-)[A-Za-z0-9_-]{20,}`), "${1}" + redactedValue, nil},                                         // Anthropic sk-ant-, OpenAI sk-proj- and sk-
	{regexp.MustCompile(`\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`), "${1}" + redactedValue, nil},                             // AWS access key id
	{regexp.MustCompile(`\b(gh[pousr]_)[A-Za-z0-9]{30,}`), "${1}" + redactedValue, nil},                                    // GitHub tokens
	{regexp.MustCompile(`\b(github_pat_)[A-Za-z0-9_]{22,}`), "${1}" + redactedValue, nil},                                  // GitHub fine-grained tokens
	{regexp.MustCompile(`\b(glpat-)[A-Za-z0-9_-]{20,}`), "${1}" + redactedValue, nil},                                      // GitLab
	{regexp.MustCompile(`\b(xox[abposr]-)[A-Za-z0-9-]{10,}`), "${1}" + redactedValue, nil},                                 // Slack
	{regexp.MustCompile(`\b([rs]k_(?:live|test)_)[A-Za-z0-9]{16,}`), "${1}" + redactedValue, nil},                          // Stripe
	{regexp.MustCompile(`\b(AIza)[0-9A-Za-z_-]{35}`), "${1}" + redactedValue, nil},                                         // Google API key
	{regexp.MustCompile(`\b(npm_)[A-Za-z0-9]{36}`), "${1}" + redactedValue, nil},                                           // npm
	{regexp.MustCompile(`\b(hf_)[A-Za-z0-9]{30,}`), "${1}" + redactedValue, nil},                                           // Hugging Face
	{regexp.MustCompile(`\b(bcn_(?:api|device|mcp)_)[A-Za-z0-9_-]{8,}`), "${1}" + redactedValue, nil},                      // Beacon's own keys
	{regexp.MustCompile(`\b(eyJ)[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), "${1}" + redactedValue, nil}, // JWT
}

func (rule secretRule) apply(value string) string {
	if rule.keep == nil {
		return rule.pattern.ReplaceAllString(value, rule.replacement)
	}
	var out []byte
	last := 0
	for _, match := range rule.pattern.FindAllStringSubmatchIndex(value, -1) {
		if match[4] >= 0 && rule.keep(value[match[4]:match[5]]) {
			continue
		}
		out = append(out, value[last:match[0]]...)
		out = rule.pattern.ExpandString(out, rule.replacement, value, match)
		last = match[1]
	}
	if out == nil {
		return value
	}
	return string(append(out, value[last:]...))
}

// assignedSecretPattern captures the value of a labeled assignment so a bare copy of it elsewhere in
// the same text is removed too.
var assignedSecretPattern = regexp.MustCompile(`(?i)\b` + secretKeyName + secretAssignment + `(` + secretValue + `)`)

// redactWindow is how far past a string's limit redaction reads before the string is cut, so a
// secret that straddles the cut is recognized whole rather than left as a recognizable prefix. It
// covers a 4096-bit RSA private key block.
const redactWindow = 4096

type PrivacyOptions struct {
	RedactSecrets bool
	StringLimit   int
}

func RedactString(value string) string {
	// Remember assignment values before replacing their labeled occurrence so
	// repeated bare copies in the same retained prompt/output are also removed.
	// This is common in model reasoning that quotes `token=value` and later
	// refers to `value` by itself.
	var assigned []string
	for _, match := range assignedSecretPattern.FindAllStringSubmatch(value, -1) {
		if len(match) > 1 && len(match[1]) >= 8 && match[1] != redactedValue {
			assigned = append(assigned, match[1])
		}
	}
	for _, rule := range secretRules {
		value = rule.apply(value)
	}
	// Each copy is searched for and removed; none of it survives into the result.
	for _, copied := range assigned {
		value = strings.ReplaceAll(value, copied, redactedValue)
	}
	return value
}

// isSecretKeyName reports whether a structured field's name says its value is a credential:
// `password`, `api_key`, `apiKey`, `X-Api-Key`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
// `client_secret`, `Cookie`. The name must end in the marker, so `input_tokens`, `token_type`,
// `author` and `PWD` are not secrets.
func isSecretKeyName(key string) bool {
	var normalized strings.Builder
	for _, r := range strings.ToLower(key) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			normalized.WriteRune(r)
		}
	}
	name := normalized.String()
	for _, suffix := range secretKeySuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

var secretKeySuffixes = []string{
	"password", "passwd", "passphrase", "secret", "token", "apikey", "accesskey", "secretkey",
	"privatekey", "authorization", "credential", "credentials", "cookie",
}

func TruncateString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	if limit < 32 {
		return value[:limit]
	}
	return value[:limit-15] + "...[truncated]"
}

// CleanString redacts before it truncates, so a cut can never leave part of a secret behind.
// Redaction reads only redactWindow bytes past the limit, which keeps a multi-megabyte command output
// as cheap as before.
func CleanString(value string, limit int, redactSecrets bool) string {
	if !redactSecrets {
		return TruncateString(value, limit)
	}
	if window := limit + redactWindow; limit > 0 && len(value) > window {
		value = value[:window]
	}
	return TruncateString(RedactString(value), limit)
}

func SanitizeMap(input map[string]interface{}, opts PrivacyOptions) map[string]interface{} {
	limit := opts.StringLimit
	if limit <= 0 {
		limit = DefaultStringLimit
	}
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		switch typed := value.(type) {
		case string:
			// A value whose field is named for a credential is one, whatever it looks like:
			// `{"password": "hunter2"}` has no shape a pattern could recognize.
			if opts.RedactSecrets && typed != "" && isSecretKeyName(key) {
				out[key] = redactedValue
				continue
			}
			out[key] = CleanString(typed, limit, opts.RedactSecrets)
		case map[string]interface{}:
			out[key] = SanitizeMap(typed, opts)
		case []interface{}:
			out[key] = SanitizeSlice(typed, opts)
		default:
			out[key] = typed
		}
	}
	return out
}

func SanitizeSlice(input []interface{}, opts PrivacyOptions) []interface{} {
	limit := opts.StringLimit
	if limit <= 0 {
		limit = DefaultStringLimit
	}
	out := make([]interface{}, len(input))
	for index, value := range input {
		switch typed := value.(type) {
		case string:
			out[index] = CleanString(typed, limit, opts.RedactSecrets)
		case map[string]interface{}:
			out[index] = SanitizeMap(typed, opts)
		case []interface{}:
			out[index] = SanitizeSlice(typed, opts)
		default:
			out[index] = typed
		}
	}
	return out
}

func SanitizeEvent(event Event, maxBytes int) Event {
	event.Message = CleanString(event.Message, DefaultStringLimit, true)
	if event.Tool != nil {
		event.Tool.Command = CleanString(event.Tool.Command, DefaultStringLimit, true)
		event.Tool.Path = TruncateString(event.Tool.Path, DefaultRawStringLimit)
	}
	if event.Command != nil {
		event.Command.Command = CleanString(event.Command.Command, DefaultStringLimit, true)
		event.Command.Output = CleanString(event.Command.Output, DefaultStringLimit, true)
	}
	// Retained content the writers have always emitted but this function never
	// saw, because the struct did not declare the fields. A diff or a block of
	// command output is exactly the kind of text that carries a credential, so
	// these get the same limit and the same secret redaction as prompt.text
	// rather than a weaker one.
	if event.File != nil {
		event.File.Diff = CleanString(event.File.Diff, DefaultStringLimit, true)
	}
	if event.Approval != nil {
		event.Approval.Reason = CleanString(event.Approval.Reason, DefaultStringLimit, true)
	}
	if event.Policy != nil {
		event.Policy.Reason = CleanString(event.Policy.Reason, DefaultStringLimit, true)
	}
	if event.Prompt != nil {
		event.Prompt.Text = CleanString(event.Prompt.Text, DefaultStringLimit, true)
	}
	if event.MCP != nil {
		event.MCP = sanitizeTyped(event.MCP, PrivacyOptions{RedactSecrets: true, StringLimit: DefaultRawStringLimit})
	}
	if event.SystemContext != nil {
		event.SystemContext = sanitizeTyped(event.SystemContext, PrivacyOptions{RedactSecrets: true, StringLimit: DefaultRawStringLimit})
	}
	if event.GenAI != nil {
		description := ""
		if event.GenAI.Tool != nil {
			description = event.GenAI.Tool.Description
		}
		event.GenAI = sanitizeTyped(event.GenAI, PrivacyOptions{RedactSecrets: true, StringLimit: DefaultRawStringLimit})
		// A tool description is text the model reads, so it gets the prompt-text limit rather than
		// the raw-attribute one: under 2 KB a padded description would hide its instructions past
		// the point the poisoning rule sees.
		if description != "" && event.GenAI.Tool != nil {
			event.GenAI.Tool.Description = CleanString(description, DefaultStringLimit, true)
		}
	}
	if event.Raw != nil {
		event.Raw = SanitizeMap(event.Raw, PrivacyOptions{RedactSecrets: true, StringLimit: DefaultRawStringLimit})
	}
	if data, err := json.Marshal(event); err == nil && len(data) > maxBytes {
		event.Truncated = true
	}
	return event
}

func sanitizeTyped[T any](input *T, opts PrivacyOptions) *T {
	if input == nil {
		return nil
	}
	data, err := json.Marshal(input)
	if err != nil {
		out := *input
		return &out
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		out := *input
		return &out
	}
	raw = SanitizeMap(raw, opts)
	data, err = json.Marshal(raw)
	if err != nil {
		out := *input
		return &out
	}
	var out T
	if err := json.Unmarshal(data, &out); err != nil {
		fallback := *input
		return &fallback
	}
	return &out
}
