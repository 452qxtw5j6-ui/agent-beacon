package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/lifecycle"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/schema"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/writer"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/gitlink"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/handoff"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/tokens"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/version"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// `beacon share` publishes one local agent session as a shared trace on beacon.sh. It is the
// only part of the CLI that uploads session content on request, so it is explicit about it: the
// session it picked is named before anything is sent, --print shows the exact payload without a
// network call, a public share asks first, and the content goes through the same sanitizer the
// runtime log uses before it is projected into messages (asymptoteobserve.BuildShareMessages).
//
// After an upload it records one session.shared event in the session's own timeline, so the local
// trace list and dashboard show the session as shared. That event is inferred bookkeeping: no
// harness collected it.

// SessionSharedAction is the runtime-log action recorded after a session is shared or refreshed.
const SessionSharedAction = "session.shared"

var (
	shareAccountLoad           = account.Load
	shareHTTPClient            = &http.Client{Timeout: 60 * time.Second}
	shareNow                   = time.Now
	shareGetenv                = os.Getenv
	shareIsTTY                 = func() bool { return isTerminal(os.Stdin) }
	shareStdin       io.Reader = os.Stdin
	// shareGitRemote reads the remote of the repository a session ran in, best effort.
	shareGitRemote = gitRemoteForDir
)

type shareOptions struct {
	session    string
	sourcePath string
	cwd        string
	harness    string
	visibility string
	title      string
	key        string
	authURL    string
	jsonOutput bool
	list       bool
	print      bool
	dryRun     bool
	yes        bool
	limit      int
	logPath    string
	storeDirs  []string
}

var shareOpts shareOptions

var shareCmd = &cobra.Command{
	Use:   "share",
	Short: "Share a local agent session as a trace on beacon.sh",
	Long: `Share one local agent session as a trace on beacon.sh, and print its link.

The session is the most recent one in the current directory unless --session, --source-path or
--cwd names another; --list shows the candidates. It is read from its runtime's own session store
when Beacon reads that runtime's store, and from Beacon's runtime log otherwise.

What is uploaded: the session's prompts, assistant text and reasoning, tool calls with their
arguments, commands, file paths and diffs, and tool output, after the same secret redaction and size
limits the runtime log applies. Paths are rewritten relative to the session's directory, and the
home directory becomes ~. Use --print to see exactly what would be sent without sending it.

Visibility: direct (the default for a new trace) means anyone with the link; private means only
you; public lists the trace in Discover for anyone, and asks for confirmation first. Re-sharing
a session updates the same trace and keeps its visibility unless --visibility is given.

Sharing needs ` + "`beacon login`" + ` (with the traces:write permission) or a Beacon API key in --key or
BEACON_API_KEY. Nothing is uploaded by hooks or in the background; only this command shares.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         func(cmd *cobra.Command, args []string) error { return shareJSONErrors(cmd, runShare(cmd)) },
}

var shareRefreshCmd = &cobra.Command{
	Use:   "refresh [external-id|session-id]",
	Short: "Upload a shared session's new messages",
	Long: `Upload the messages a session has gained since it was shared.

The argument is the trace's external id (<runtime>:<session-id>, as ` + "`beacon share --json`" + ` prints
it) or a session id or unique prefix; without one, the most recent session in the current directory.
beacon.sh reports the last message it has, and only the messages after it are sent. Re-sending is
harmless, so a refresh that fails part way can simply be run again. The trace's visibility is not
changed.`,
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return shareJSONErrors(cmd, runShareRefresh(cmd, args))
	},
}

func init() {
	rootCmd.AddCommand(shareCmd)
	shareCmd.AddCommand(shareRefreshCmd)
	for _, c := range []*cobra.Command{shareCmd, shareRefreshCmd} {
		f := c.Flags()
		f.StringVar(&shareOpts.harness, "harness", "auto", "Only sessions of this runtime ("+strings.Join(handoff.RuntimeNames(), ", ")+"), or auto")
		f.StringVar(&shareOpts.key, "key", "", "Beacon API key (bcn_api_...) to share with instead of your sign-in")
		f.StringVar(&shareOpts.authURL, "auth-url", "", "Beacon service an API key is sent to (defaults to "+account.DefaultBaseURL+", or "+account.BaseURLEnv+")")
		f.BoolVar(&shareOpts.jsonOutput, "json", false, "Print the result as JSON")
		f.StringVar(&shareOpts.logPath, "log-path", "", "Runtime JSONL log to read sessions from and record the share in (default the local runtime log)")
		f.StringArrayVar(&shareOpts.storeDirs, "store-dir", nil, "Read a runtime's sessions from this directory, as <runtime>=<path> (repeatable)")
		f.StringVar(&shareOpts.cwd, "cwd", "", "Use the most recent session that ran in this directory (default: the current directory)")
		f.BoolVar(&shareOpts.print, "print", false, "Print the payload that would be uploaded and send nothing")
		f.BoolVar(&shareOpts.dryRun, "dry-run", false, "Same as --print")
		f.StringVar(&shareOpts.title, "title", "", "Title for the shared trace (default: the session's title or first prompt)")
	}
	f := shareCmd.Flags()
	f.StringVar(&shareOpts.session, "session", "", "Session id, or a unique prefix of at least 6 characters")
	f.StringVar(&shareOpts.sourcePath, "source-path", "", "The session's file in its runtime's store")
	f.StringVar(&shareOpts.visibility, "visibility", asymptoteobserve.ShareVisibilityDirect, "Who can view the trace: public, direct (anyone with the link) or private")
	f.BoolVar(&shareOpts.list, "list", false, "List the sessions that could be shared, newest first, and share nothing")
	f.IntVar(&shareOpts.limit, "limit", 20, "With --list, the most sessions to show (0 for all)")
	f.BoolVar(&shareOpts.yes, "yes", false, "Share publicly without asking")
	shareCmd.MarkFlagsMutuallyExclusive("session", "source-path", "cwd")
}

// shareJSONErrors also reports a failure as {"ok":false,...} on stdout under --json, so a script
// reading stdout always gets a document.
func shareJSONErrors(cmd *cobra.Command, err error) error {
	if err != nil && shareOpts.jsonOutput {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"ok": false, "error": err.Error()})
	}
	return err
}

type shareResult struct {
	TraceID      string `json:"trace_id"`
	ExternalID   string `json:"external_id"`
	SharedURL    string `json:"shared_url"`
	Visibility   string `json:"visibility"`
	AgentID      string `json:"agent_id"`
	MessageCount int    `json:"message_count"`
	// Uploaded is how many messages this run sent; on a first share it equals the session's count.
	Uploaded int `json:"uploaded"`
}

// sharePayload is what --print shows: the trace metadata of the PUT request and every message the
// batch requests would carry, in order.
type sharePayload struct {
	ExternalID string                            `json:"external_id"`
	Trace      asymptoteobserve.ShareTraceV1     `json:"trace"`
	Messages   []asymptoteobserve.ShareMessageV1 `json:"messages"`
}

func (o shareOptions) printOnly() bool { return o.print || o.dryRun }

func runShare(cmd *cobra.Command) error {
	if err := validateShareFlags(cmd); err != nil {
		return err
	}
	harness, err := shareHarness()
	if err != nil {
		return err
	}
	if shareOpts.list {
		return runShareList(cmd, harness)
	}
	subject, err := resolveShareSubject(harness, shareOpts.session)
	if err != nil {
		return err
	}
	payload, err := buildSharePayload(subject)
	if err != nil {
		return err
	}
	if cmd.Flags().Changed("visibility") {
		payload.Trace.Visibility = shareOpts.visibility
	}
	errOut := cmd.ErrOrStderr()
	if shareOpts.printOnly() {
		return writeIndentedJSON(cmd.OutOrStdout(), payload)
	}
	if payload.Trace.Visibility == asymptoteobserve.ShareVisibilityPublic && !shareOpts.yes {
		if err := confirmPublicShare(errOut, subject.session, len(payload.Messages)); err != nil {
			return err
		}
	}
	client, err := newShareClient()
	if err != nil {
		return err
	}
	if !shareOpts.jsonOutput {
		fmt.Fprintf(errOut, "Sharing %s session %s (%d messages)%s.\n", subject.session.Harness, subject.session.ID, len(payload.Messages), shareSourceNote(subject))
	}
	ctx := commandContext(cmd)
	trace, err := client.PutTrace(ctx, payload.ExternalID, payload.Trace)
	if err != nil {
		return err
	}
	uploaded, err := client.PutMessages(ctx, payload.ExternalID, payload.Messages)
	if err != nil {
		return fmt.Errorf("the trace was created at %s, but uploading its messages failed (run the same command again to retry): %w", trace.URL, err)
	}
	result := shareResult{
		TraceID:      trace.ID,
		ExternalID:   payload.ExternalID,
		SharedURL:    trace.URL,
		Visibility:   trace.Visibility,
		AgentID:      payload.Trace.AgentID,
		MessageCount: uploaded.MessageCount,
		Uploaded:     len(payload.Messages),
	}
	if uploaded.Batches == 0 {
		result.MessageCount = trace.MessageCount
	}
	if err := recordShareEvent(subject.session, result, false); err != nil {
		fmt.Fprintf(errOut, "warning: the session was shared, but the runtime log was not updated: %v\n", err)
	}
	return printShareResult(cmd, result)
}

func runShareRefresh(cmd *cobra.Command, args []string) error {
	harness, err := shareHarness()
	if err != nil {
		return err
	}
	id := ""
	if len(args) == 1 {
		id = strings.TrimSpace(args[0])
		if shareOpts.cwd != "" {
			return errors.New("pass a session or --cwd, not both")
		}
		if h, sessionID, ok := parseShareExternalID(id); ok {
			if harness != "" && h != harness {
				return fmt.Errorf("%s is a %s trace, not %s", id, h, harness)
			}
			harness, id = h, sessionID
		} else if strings.Contains(id, ":sha256-") {
			return fmt.Errorf("%s names a session by a digest of its id; pass the session id instead", id)
		}
	}
	subject, err := resolveShareSubject(harness, id)
	if err != nil {
		return err
	}
	payload, err := buildSharePayload(subject)
	if err != nil {
		return err
	}
	if shareOpts.printOnly() {
		return writeIndentedJSON(cmd.OutOrStdout(), payload)
	}
	client, err := newShareClient()
	if err != nil {
		return err
	}
	ctx := commandContext(cmd)
	state, found, err := client.GetTrace(ctx, payload.ExternalID)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s is not shared yet: run `beacon share --session %s` first", payload.ExternalID, subject.session.ID)
	}
	pending := messagesAfter(payload.Messages, state.LastMessageID, state.MaxOrder)
	trace, err := client.PutTrace(ctx, payload.ExternalID, payload.Trace)
	if err != nil {
		return err
	}
	uploaded, err := client.PutMessages(ctx, payload.ExternalID, pending)
	if err != nil {
		return err
	}
	result := shareResult{
		TraceID:      trace.ID,
		ExternalID:   payload.ExternalID,
		SharedURL:    trace.URL,
		Visibility:   trace.Visibility,
		AgentID:      payload.Trace.AgentID,
		MessageCount: state.MessageCount,
		Uploaded:     len(pending),
	}
	if uploaded.Batches > 0 {
		result.MessageCount = uploaded.MessageCount
	}
	if err := recordShareEvent(subject.session, result, true); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: the trace was refreshed, but the runtime log was not updated: %v\n", err)
	}
	return printShareResult(cmd, result)
}

// messagesAfter returns the messages after the one beacon.sh reported last. With no last id it goes
// by the order number. When the last id is not in this projection (the session was shared from
// another source, or its earlier messages changed), it returns everything: an upsert of what the
// server already has changes nothing.
func messagesAfter(messages []asymptoteobserve.ShareMessageV1, lastID string, maxOrder int) []asymptoteobserve.ShareMessageV1 {
	if lastID != "" {
		for i, m := range messages {
			if m.ID == lastID {
				return messages[i+1:]
			}
		}
	}
	if maxOrder > 0 && maxOrder <= len(messages) && lastID == "" {
		return messages[maxOrder:]
	}
	return messages
}

func validateShareFlags(cmd *cobra.Command) error {
	if !asymptoteobserve.ValidShareVisibility(shareOpts.visibility) {
		return fmt.Errorf("--visibility must be public, direct or private, not %q", shareOpts.visibility)
	}
	if shareOpts.list {
		switch {
		case shareOpts.session != "" || shareOpts.sourcePath != "":
			return errors.New("--list shows candidates; combine it with --cwd or --harness, not --session or --source-path")
		case shareOpts.printOnly():
			return errors.New("--list and --print cannot be combined")
		}
	}
	if shareOpts.limit < 0 {
		return errors.New("--limit cannot be negative")
	}
	return nil
}

func shareHarness() (string, error) {
	value := strings.TrimSpace(shareOpts.harness)
	if value == "" || strings.EqualFold(value, "auto") {
		return "", nil
	}
	return handoff.ParseHarness(value)
}

func shareLogPath() string {
	return lifecycle.ResolveRuntimeLog(true, shareOpts.logPath).EffectiveLogPath
}

func shareStoreDirs() (handoff.StoreDirs, error) {
	dirs := handoff.StoreDirs{}
	for _, entry := range shareOpts.storeDirs {
		name, dir, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(name) == "" || dir == "" {
			return nil, fmt.Errorf("--store-dir %q: want <runtime>=<path>", entry)
		}
		harness, err := handoff.ParseHarness(name)
		if err != nil {
			return nil, fmt.Errorf("--store-dir %q: %w", entry, err)
		}
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, err
		}
		dirs[harness] = abs
	}
	return dirs, nil
}

// shareDirectory is the directory --cwd names, absolute, or the current one.
func shareDirectory() (string, error) {
	dir := strings.TrimSpace(shareOpts.cwd)
	if dir == "" {
		dir = "."
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("resolve --cwd %s: %w", dir, err)
	}
	return abs, nil
}

// shareSubject is a session to share and, when it came from the runtime log, its events.
type shareSubject struct {
	session   handoff.Session
	fromLog   bool
	logEvents []schema.Event
}

func shareSourceNote(subject shareSubject) string {
	if subject.fromLog {
		return " from Beacon's runtime log"
	}
	return ""
}

// resolveShareSubject finds the session to share: by id (prefix ok), by its store file, or as the
// most recent session in a directory. Stores come first, then the runtime log.
func resolveShareSubject(harness, id string) (shareSubject, error) {
	dirs, err := shareStoreDirs()
	if err != nil {
		return shareSubject{}, err
	}
	sources := handoffSources(dirs)
	switch {
	case id != "":
		session, findErr := handoff.Find(sources, harness, id)
		if findErr == nil {
			return shareSubject{session: session}, nil
		}
		var notFound *handoff.NotFoundError
		if !errors.As(findErr, &notFound) {
			return shareSubject{}, findErr
		}
		logPath := shareLogPath()
		session, events, found, err := handoff.LogSession(logPath, id, harness)
		if err != nil {
			return shareSubject{}, fmt.Errorf("read runtime log %s: %w", logPath, err)
		}
		if !found || (harness != "" && session.Harness != harness) {
			return shareSubject{}, fmt.Errorf("%w; not in the runtime log %s either (`beacon share --list` shows what is available)", notFound, logPath)
		}
		return shareSubject{session: session, fromLog: true, logEvents: events}, nil
	case strings.TrimSpace(shareOpts.sourcePath) != "":
		return resolveShareSourcePath(sources, harness, shareOpts.sourcePath)
	default:
		dir, err := shareDirectory()
		if err != nil {
			return shareSubject{}, err
		}
		candidates, err := shareCandidates(sources, harness, dir, 1)
		if err != nil {
			return shareSubject{}, err
		}
		if len(candidates) == 0 {
			return shareSubject{}, fmt.Errorf("no agent session found in %s; pass --session, or --cwd for another directory (`beacon share --list --cwd DIR`)", dir)
		}
		// A session of a runtime whose store Beacon reads is read from that store; one the store has
		// lost since falls back to the log when its events are read (shareEvents).
		session := candidates[0]
		if handoff.ReadsStore(session.Harness) {
			return shareSubject{session: session}, nil
		}
		return resolveShareLog(session)
	}
}

func resolveShareLog(session handoff.Session) (shareSubject, error) {
	logPath := shareLogPath()
	found, events, ok, err := handoff.LogSession(logPath, session.ID, session.Harness)
	if err != nil {
		return shareSubject{}, fmt.Errorf("read runtime log %s: %w", logPath, err)
	}
	if !ok {
		return shareSubject{}, fmt.Errorf("%s session %s is not in the runtime log %s", session.Harness, session.ID, logPath)
	}
	return shareSubject{session: found, fromLog: true, logEvents: events}, nil
}

func resolveShareSourcePath(sources []handoff.Source, harness, path string) (shareSubject, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return shareSubject{}, err
	}
	if _, err := os.Stat(abs); err != nil {
		return shareSubject{}, fmt.Errorf("--source-path %s: %w", path, err)
	}
	resolved, _ := filepath.EvalSymlinks(abs)
	sessions, listErr := handoff.List(sources, handoff.Filter{Harness: harness, IncludeSubagents: true})
	for _, session := range sessions {
		if session.SourcePath == "" {
			continue
		}
		if session.SourcePath == abs || (resolved != "" && evalSymlinks(session.SourcePath) == resolved) {
			return shareSubject{session: session}, nil
		}
	}
	if listErr != nil {
		return shareSubject{}, fmt.Errorf("no session store lists %s (some stores could not be read: %v)", path, listErr)
	}
	return shareSubject{}, fmt.Errorf("no session store Beacon reads lists %s as a session file", path)
}

func evalSymlinks(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}

// shareCandidates lists the sessions in dir, newest first: those in the runtimes' own stores, then
// sessions only Beacon's runtime log has. A store that cannot be read is skipped; the log still
// answers for it.
func shareCandidates(sources []handoff.Source, harness, dir string, limit int) ([]handoff.Session, error) {
	stored, _ := handoff.List(sources, handoff.Filter{Harness: harness, Directory: dir})
	logged, logErr := handoff.LogSessions(shareLogPath(), handoff.Filter{Harness: harness, Directory: dir})
	if logErr != nil && !errors.Is(logErr, os.ErrNotExist) && len(stored) == 0 {
		return nil, fmt.Errorf("read runtime log: %w", logErr)
	}
	seen := map[string]bool{}
	var out []handoff.Session
	for _, s := range stored {
		seen[s.Harness+"\x00"+s.ID] = true
		out = append(out, s)
	}
	for _, s := range logged {
		if !seen[s.Harness+"\x00"+s.ID] {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func runShareList(cmd *cobra.Command, harness string) error {
	dirs, err := shareStoreDirs()
	if err != nil {
		return err
	}
	dir, err := shareDirectory()
	if err != nil {
		return err
	}
	sessions, err := shareCandidates(handoffSources(dirs), harness, dir, shareOpts.limit)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if shareOpts.jsonOutput {
		if sessions == nil {
			sessions = []handoff.Session{}
		}
		return json.NewEncoder(out).Encode(map[string]any{"ok": true, "data": map[string]any{"directory": dir, "sessions": sessions}})
	}
	printHandoffSessions(out, sessions, shareNow())
	return nil
}

// shareEvents reads the subject's events: from its runtime's store, or from the runtime log when the
// session came from there or its store has lost it since it was listed.
func shareEvents(subject shareSubject) (shareSubject, []schema.Event, error) {
	if subject.fromLog {
		return subject, subject.logEvents, nil
	}
	dirs, err := shareStoreDirs()
	if err != nil {
		return subject, nil, err
	}
	events, err := handoff.Events(handoffSources(dirs), subject.session)
	if err == nil {
		return subject, events, nil
	}
	if !errors.Is(err, handoff.ErrNotFound) {
		return subject, nil, fmt.Errorf("read %s session %s: %w", subject.session.Harness, subject.session.ID, err)
	}
	logSubject, logErr := resolveShareLog(subject.session)
	if logErr != nil {
		return subject, nil, logErr
	}
	return logSubject, logSubject.logEvents, nil
}

func buildSharePayload(subject shareSubject) (sharePayload, error) {
	subject, events, err := shareEvents(subject)
	if err != nil {
		return sharePayload{}, err
	}
	session := subject.session
	sort.SliceStable(events, func(i, j int) bool { return shareEventTime(events[i]).Before(shareEventTime(events[j])) })
	opts := asymptoteobserve.ShareOptions{WorkingDirectory: session.Directory}
	messages := asymptoteobserve.BuildShareMessagesWithOptions(events, opts)
	if len(messages) == 0 {
		return sharePayload{}, fmt.Errorf("%s session %s has nothing to share yet", session.Harness, session.ID)
	}
	trace := asymptoteobserve.ShareMetadataFromEventsWithOptions(events, opts)
	agent := asymptoteobserve.NormalizeHarnessName(session.Harness)
	if agent == "" {
		agent = session.Harness
	}
	trace.AgentID = agent
	trace.SourceSessionID = session.ID
	if title := strings.TrimSpace(shareOpts.title); title != "" {
		trace.Title = asymptoteobserve.ShareTitle(title)
	} else if title := asymptoteobserve.ShareTitle(session.Title); title != "" {
		trace.Title = asymptoteobserve.RedactString(title)
	}
	if trace.GitBranch == "" {
		trace.GitBranch = asymptoteobserve.ShareBranch(session.Branch)
	}
	if trace.GitRemoteURL == "" && session.Directory != "" {
		trace.GitRemoteURL = gitlink.SanitizeRemoteURL(shareGitRemote(session.Directory))
		if trace.ProjectName == "" || trace.ProjectName == filepath.Base(session.Directory) {
			if name := strings.TrimSuffix(lastURLSegment(trace.GitRemoteURL), ".git"); name != "" {
				trace.ProjectName = name
			}
		}
	}
	if session.Subagent && session.ParentID != "" {
		trace.RelatedTo = asymptoteobserve.ShareExternalID(session.Harness, session.ParentID)
		trace.RelationshipType = asymptoteobserve.ShareRelationshipSubagent
	}
	// The token aggregator resolves cumulative metric series and live-versus-backfill overlap,
	// which a plain sum of every event does not. Cost is what runtimes reported, never an estimate.
	totals := tokens.Aggregate(events, tokens.Options{}).Totals
	usage := asymptoteobserve.ShareTokenUsageV1{
		InputTokens:              totals.InputTokens,
		OutputTokens:             totals.OutputTokens,
		CacheReadInputTokens:     totals.CacheReadInputTokens,
		CacheCreationInputTokens: totals.CacheCreationInputTokens,
		ReasoningOutputTokens:    totals.ReasoningOutputTokens,
	}
	trace.TokenUsage, trace.CostUSD = nil, nil
	if !usage.IsZero() {
		trace.TokenUsage = &usage
	}
	if totals.CostUSD > 0 {
		cost := totals.CostUSD
		trace.CostUSD = &cost
	}
	return sharePayload{
		ExternalID: asymptoteobserve.ShareExternalID(session.Harness, session.ID),
		Trace:      trace,
		Messages:   messages,
	}, nil
}

func shareEventTime(event schema.Event) time.Time {
	ts, err := schema.ParseTimestamp(event.Timestamp)
	if err != nil {
		return time.Time{}
	}
	return ts
}

func lastURLSegment(value string) string {
	value = strings.TrimRight(value, "/")
	if i := strings.LastIndexAny(value, "/:"); i >= 0 {
		return value[i+1:]
	}
	return ""
}

// gitRemoteForDir reads the origin remote of the repository at dir, or "" when there is none. It
// is a local read of git's config; nothing is fetched.
func gitRemoteForDir(dir string) string {
	if info, err := os.Stat(dir); err != nil || !info.IsDir() {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "config", "--get", "remote.origin.url").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func confirmPublicShare(errOut io.Writer, session handoff.Session, messages int) error {
	if !shareIsTTY() || isCIEnvironment() {
		return errors.New("a public trace is listed for anyone to find; pass --yes to share publicly without a terminal to confirm")
	}
	fmt.Fprintf(errOut, "Share %s session %s (%d messages) publicly? Anyone can find and read it in Discover. [y/N] ", session.Harness, session.ID, messages)
	if !confirmNo(shareStdin) {
		return errors.New("not shared")
	}
	return nil
}

func newShareClient() (*account.ShareClient, error) {
	cred, err := account.ResolveShareCredential(account.ResolveShareCredentialOptions{
		Key:     shareOpts.key,
		BaseURL: shareOpts.authURL,
		Load:    shareAccountLoad,
		Getenv:  shareGetenv,
		Now:     shareNow(),
	})
	if err != nil {
		return nil, err
	}
	return account.NewShareClient(cred, shareHTTPClient)
}

func parseShareExternalID(value string) (harness, sessionID string, ok bool) {
	name, rest, found := strings.Cut(value, ":")
	if !found || rest == "" || strings.HasPrefix(rest, "sha256-") || !asymptoteobserve.ValidShareExternalID(value) {
		return "", "", false
	}
	h, err := handoff.ParseHarness(name)
	if err != nil {
		return "", "", false
	}
	return h, rest, true
}

// recordShareEvent writes the session.shared event into the session's own timeline, with the
// sharing fields the trace list reads (shared_url, visibility, shared_at, last_refreshed_at).
func recordShareEvent(session handoff.Session, result shareResult, refresh bool) error {
	event := shareRecordEvent(session, result, refresh, shareNow())
	_, err := writer.AppendEvent(event, writer.Options{Path: shareLogPath(), UserMode: true})
	return err
}

func shareRecordEvent(session handoff.Session, result shareResult, refresh bool, now time.Time) schema.Event {
	verb := "shared"
	if refresh {
		verb = "refreshed"
	}
	event := schema.NewEvent(schema.NewEventOptions{
		Action:       SessionSharedAction,
		Category:     "session",
		Severity:     schema.SeverityInfo,
		AgentVersion: version.GetVersion(),
		Harness:      schema.HarnessInfo{Name: session.Harness},
		Fidelity:     asymptoteobserve.FidelityInferred,
		Message:      fmt.Sprintf("session %s to beacon.sh (%s, %d messages)", verb, result.Visibility, result.MessageCount),
	})
	event.Timestamp = schema.FormatTimestamp(now)
	event.Session = &schema.SessionInfo{ID: session.ID, WorkingDirectory: session.Directory}
	stamp := now.UTC().Format(time.RFC3339)
	event.Raw = map[string]interface{}{
		"shared_url":        result.SharedURL,
		"visibility":        result.Visibility,
		"shared_trace_id":   result.TraceID,
		"external_id":       result.ExternalID,
		"last_refreshed_at": stamp,
	}
	if !refresh {
		event.Raw["shared_at"] = stamp
	}
	return event
}

func printShareResult(cmd *cobra.Command, result shareResult) error {
	out := cmd.OutOrStdout()
	if shareOpts.jsonOutput {
		return json.NewEncoder(out).Encode(map[string]any{"ok": true, "data": result})
	}
	fmt.Fprintln(out, result.SharedURL)
	fmt.Fprintf(cmd.ErrOrStderr(), "%s, %d messages (%d sent). External id: %s\n", result.Visibility, result.MessageCount, result.Uploaded, result.ExternalID)
	return nil
}
