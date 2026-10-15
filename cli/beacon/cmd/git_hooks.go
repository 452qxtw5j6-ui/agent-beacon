package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/gitlink"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// gitHookBudget bounds the post-commit hook. Linking reads recent runtime log and writes one
// note, which takes milliseconds on a quiet endpoint and well under a second on a busy one; the
// bound is for the case nothing anticipated, because a person is waiting on `git commit`.
var gitHookBudget = 3 * time.Second

var gitSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Install git hooks that link each new commit to the sessions that wrote it",
	Long: `Install git hooks that link each new commit to the sessions that wrote it.

Beacon adds post-commit and post-rewrite hooks to the repository. A hook already there keeps working: Beacon adds a
marked block to it and a separate beacon-post-commit script beside it, and ` + "`beacon git remove`" + `
takes out exactly that. It also sets notes.rewriteRef, so ` + "`git commit --amend`" + ` and ` + "`git rebase`" + `
carry links to the rewritten commits.

The hook reads the local runtime log and writes a git note. It never touches the network, never
fails a commit, and skips rebases, cherry-picks and reverts. BEACON_GIT_HOOKS=0 turns it off for one
command.`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runGitSetup,
}

var gitRemoveCmd = &cobra.Command{
	Use:          "remove",
	Short:        "Remove Beacon's git hooks from the repository (links already written stay)",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runGitRemove,
}

var gitStatusCmd = &cobra.Command{
	Use:          "status",
	Short:        "Show whether this repository links commits automatically",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runGitStatus,
}

var gitHookCmd = &cobra.Command{
	Use:    "hook",
	Short:  "Entry points the installed git hooks call",
	Hidden: true,
}

var gitHookPostCommitCmd = &cobra.Command{
	Use:          "post-commit",
	Short:        "Link HEAD to the sessions that wrote it (called by the post-commit hook)",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runGitHookPostCommit,
}

var gitHookPostRewriteCmd = &cobra.Command{
	Use:          "post-rewrite [amend|rebase]",
	Short:        "Tidy the notes on rewritten commits (called by the post-rewrite hook)",
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE:         runGitHookPostRewrite,
}

var gitSetupOpts struct {
	allowHooksPath  bool
	shareNotes      bool
	shareSessions   bool
	shareVisibility string
	yes             bool
}

func runGitSetup(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	repo, err := gitRepo(ctx)
	if err != nil {
		return err
	}
	opts := gitlink.InstallOptions{
		BeaconPath:     beaconExecutable(),
		AllowHooksPath: gitSetupOpts.allowHooksPath,
	}
	if cmd.Flags().Changed("share-notes") {
		share := gitSetupOpts.shareNotes
		opts.ShareNotes = &share
	}
	shareSessions := cmd.Flags().Changed("share-sessions") && gitSetupOpts.shareSessions
	visibility := strings.ToLower(strings.TrimSpace(gitSetupOpts.shareVisibility))
	if shareSessions {
		if opts.ShareNotes != nil && !*opts.ShareNotes {
			return errors.New("--share-sessions shares sessions from the pre-push hook that --share-notes installs; it cannot be combined with --share-notes=false")
		}
		if !asymptoteobserve.ValidShareVisibility(visibility) {
			return fmt.Errorf("--share-visibility must be public, direct or private, not %q", gitSetupOpts.shareVisibility)
		}
		if visibility == asymptoteobserve.ShareVisibilityPublic && !gitSetupOpts.yes {
			if !shareIsTTY() || isCIEnvironment() {
				return errors.New("public sharing lists every session linked to a pushed commit in Discover; pass --yes to set it up without a terminal to confirm")
			}
			fmt.Fprint(cmd.ErrOrStderr(), "Share every session linked to a pushed commit publicly? Anyone can find and read them in Discover. [y/N] ")
			if !confirmNo(shareStdin) {
				return errors.New("nothing was changed")
			}
		}
		share := true
		opts.ShareNotes = &share
	}
	result, err := gitlink.InstallHooks(ctx, repo, opts)
	out := cmd.OutOrStdout()
	if err != nil {
		switch {
		case errors.Is(err, gitlink.ErrHooksPathSet):
			return fmt.Errorf("%w; git runs this repository's hooks from %s, which a hook manager usually owns.\n"+
				"Add this line to its post-commit hook:\n\n    %s\n\n"+
				"or run `beacon git setup --hooks-path` to install into that directory anyway", err, result.Hooks.Dir, gitlink.HookCall("post-commit"))
		case errors.Is(err, gitlink.ErrForeignHook):
			var foreign *gitlink.ForeignHookError
			hook := "post-commit"
			if errors.As(err, &foreign) && foreign.Hook != "" {
				hook = foreign.Hook
			}
			msg := fmt.Sprintf("%v; Beacon only edits shell hooks, so nothing was installed. Call Beacon from that %s hook instead:\n\n    %s", err, hook, gitlink.HookCall(hook))
			if hook == gitlink.ShareHook {
				msg += "\n\nor run `beacon git setup` without --share-notes to link commits without sharing them"
			}
			return errors.New(msg)
		}
		return err
	}
	sessionsChanged := ""
	switch {
	case shareSessions:
		if err := gitlink.SetShareSessions(ctx, repo, true, visibility); err != nil {
			return err
		}
		sessionsChanged = "on"
	case cmd.Flags().Changed("share-sessions") || (opts.ShareNotes != nil && !*opts.ShareNotes):
		if enabled, _ := gitlink.ShareSessionsConfig(ctx, repo); enabled {
			if err := gitlink.SetShareSessions(ctx, repo, false, ""); err != nil {
				return err
			}
			sessionsChanged = "off"
		}
	}
	if gitOpts.jsonOutput {
		return writeIndentedJSON(out, struct {
			gitlink.InstallResult
			ShareSessions string `json:"share_sessions,omitempty"`
		}{result, sessionsChanged})
	}
	for _, r := range result.Reports {
		fmt.Fprintf(out, "%-9s %s (calls %s)\n", r.Action, r.Path, filepath.Base(r.Script))
	}
	switch sessionsChanged {
	case "on":
		fmt.Fprintf(out, "set       %s = true, %s = %s\n", gitlink.ShareSessionsKey, gitlink.ShareVisibilityKey, visibility)
	case "off":
		fmt.Fprintf(out, "unset     %s\n", gitlink.ShareSessionsKey)
	}
	if result.RewriteRefSet {
		fmt.Fprintf(out, "set       notes.rewriteRef = %s\n", gitlink.NotesRef)
	}
	for _, remote := range result.FetchAdded {
		fmt.Fprintf(out, "set       remote.%s.fetch += %s\n", remote, gitlink.FetchRefspec(remote))
	}
	for _, remote := range result.FetchRemoved {
		fmt.Fprintf(out, "unset     remote.%s.fetch %s\n", remote, gitlink.FetchRefspec(remote))
	}
	if opts.ShareNotes != nil && *opts.ShareNotes {
		fmt.Fprintf(out, "Commit links are shared: each `git push` also pushes %s to the same remote, and `git fetch` brings teammates' links.\n", gitlink.NotesRef)
	}
	if sessionsChanged == "on" {
		fmt.Fprintf(out, "Each `git push` also shares the agent sessions linked to the pushed commits to beacon.sh (%s), using your `beacon login` or BEACON_API_KEY, and writes their links into the notes.\n", visibility)
	}
	fmt.Fprintln(out, "New commits in this repository are linked to the agent sessions that wrote them.")
	fmt.Fprintln(out, "See them with `beacon git notes`; link an older commit with `beacon git link <commit>`.")
	return nil
}

func runGitRemove(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	repo, err := gitRepo(ctx)
	if err != nil {
		return err
	}
	result, err := gitlink.RemoveHooks(ctx, repo)
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if gitOpts.jsonOutput {
		return writeIndentedJSON(out, result)
	}
	for _, r := range result.Reports {
		fmt.Fprintf(out, "%-9s %s\n", r.Action, r.Path)
	}
	if result.RewriteRefRemoved {
		fmt.Fprintf(out, "unset     notes.rewriteRef = %s\n", gitlink.NotesRef)
	}
	if result.ShareSessionsRemoved {
		fmt.Fprintf(out, "unset     %s\n", gitlink.ShareSessionsKey)
	}
	for _, remote := range result.FetchRemoved {
		fmt.Fprintf(out, "unset     remote.%s.fetch %s\n", remote, gitlink.FetchRefspec(remote))
	}
	fmt.Fprintf(out, "Links already written stay in %s.\n", gitlink.NotesRef)
	return nil
}

func runGitStatus(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	repo, err := gitRepo(ctx)
	if err != nil {
		return err
	}
	status, err := gitlink.HookStatus(ctx, repo)
	if err != nil {
		return err
	}
	overruns := gitlink.ScanBudgetOverruns(gitRuntimeLogPath(), repo.Root, time.Now().Add(-gitOverrunWindow))
	out := cmd.OutOrStdout()
	if gitOpts.jsonOutput {
		return writeIndentedJSON(out, struct {
			gitlink.Status
			Installed      bool                   `json:"installed"`
			BudgetOverruns gitlink.BudgetOverruns `json:"budget_overruns"`
		}{status, status.Installed(), overruns})
	}
	fmt.Fprintf(out, "repository  %s\n", repo.Root)
	fmt.Fprintf(out, "hooks       %s\n", status.Hooks.Dir)
	if status.Hooks.HooksPath != "" {
		fmt.Fprintf(out, "            (core.hooksPath = %s)\n", status.Hooks.HooksPath)
	}
	for _, st := range status.States {
		state := "not installed"
		switch {
		case st.Installed && st.Outdated:
			state = "installed, from an earlier Beacon (run `beacon git setup` to update it)"
		case st.Installed:
			state = "installed"
		case st.BlockPresent:
			state = "broken: the hook calls a script that is missing (run `beacon git setup`)"
		case st.ScriptExists:
			state = "broken: the script exists but the hook does not call it (run `beacon git setup`)"
		}
		fmt.Fprintf(out, "%-11s %s\n", st.Hook, state)
	}
	rewrite := "not set"
	if status.RewriteRef {
		rewrite = "set"
	}
	fmt.Fprintf(out, "rewriteRef  %s\n", rewrite)
	sharing := "off (`beacon git setup --share-notes` turns it on)"
	if status.Sharing {
		sharing = "on: pushes share links"
	}
	fmt.Fprintf(out, "sharing     %s\n", sharing)
	for _, remote := range status.FetchRemotes {
		fmt.Fprintf(out, "            fetches from %s bring its links\n", remote)
	}
	sessions := "off (`beacon git setup --share-sessions` turns it on)"
	if status.ShareSessions {
		vis := status.ShareVisibility
		if vis == "" {
			vis = asymptoteobserve.ShareVisibilityDirect
		}
		sessions = "on: pushes share linked sessions to beacon.sh (" + vis + ")"
	}
	fmt.Fprintf(out, "sessions    %s\n", sessions)
	fmt.Fprintf(out, "overruns    %s\n", describeGitOverruns(overruns))
	return nil
}

// describeGitOverruns is the status line for the hook runs in this repository that ran out of time
// recently. A run cut short is a commit left unlinked (or a link event, note or share left
// unrecorded), which nothing else on the terminal ever says.
func describeGitOverruns(o gitlink.BudgetOverruns) string {
	days := int(gitOverrunWindow / (24 * time.Hour))
	if o.Last == nil {
		return fmt.Sprintf("none in the last %d days", days)
	}
	return fmt.Sprintf("%d hook run(s) ran out of time in the last %d days, %d cut short; last %s: %s",
		o.Count, days, o.CutShort, o.Last.Timestamp, o.Last.Describe())
}

// runGitHookPostCommit is the post-commit hook. It never returns an error: git ignores a
// post-commit hook's exit status anyway, and a hook that printed a stack of errors on every commit
// in a repository with no agent activity would be worse than one that stayed quiet. A run that
// runs out of its budget records one git.hook_budget_exceeded event, still silently.
func runGitHookPostCommit(cmd *cobra.Command, _ []string) error {
	if os.Getenv(gitlink.DisableEnv) == "0" {
		return nil
	}
	run, ctx, cancel := startGitHook(cmd.Context(), "post-commit", gitHookBudget)
	defer cancel()
	result, repoRoot, ran := gitPostCommit(ctx, run)
	finishGitHook(ctx, run, repoRoot)
	if gitOpts.jsonOutput && ran {
		_ = writeIndentedJSON(cmd.OutOrStdout(), result)
	}
	return nil
}

// gitPostCommit links HEAD and records the link events, marking each step on run. It returns the
// repository's work tree for the budget event, empty when the repository was never resolved.
func gitPostCommit(ctx context.Context, run *gitlink.HookRun) (gitlink.Result, string, bool) {
	run.Phase("open_repository")
	repo, err := gitRepo(ctx)
	if err == nil && gitlink.ReplayInProgress(ctx, repo) {
		return gitlink.Result{}, repo.Root, false
	}
	if err == nil {
		// The replay check reads its answers through git and treats a failed read as "no replay",
		// so a deadline that passed during it shows only on the context.
		err = ctx.Err()
	}
	if run.Check(ctx, err); err != nil {
		return gitlink.Result{}, repo.Root, false
	}
	run.Phase("attribute")
	result, err := gitlink.Attribute(ctx, repo, gitlink.Options{LogPath: gitRuntimeLogPath(), ShareURL: gitShareURLLookup(gitRuntimeLogPath())})
	if run.Check(ctx, err); err != nil {
		return gitlink.Result{}, repo.Root, false
	}
	// The note is the link; the event is its echo in the session's timeline. A log the hook cannot
	// write (a system-mode log this user may not append to) costs only the echo.
	run.Phase("record_link_event")
	run.Check(ctx, recordLinkEvents(ctx, repo, result))
	return result, repo.Root, true
}

// runGitHookPostRewrite reads git's `<old-sha> <new-sha> [<extra>]` lines and normalizes the note
// on each new commit. Like the post-commit hook, it never returns an error.
func runGitHookPostRewrite(cmd *cobra.Command, _ []string) error {
	if os.Getenv(gitlink.DisableEnv) == "0" {
		return nil
	}
	run, ctx, cancel := startGitHook(cmd.Context(), "post-rewrite", gitHookBudget)
	defer cancel()
	var repo gitlink.Repo
	defer func() { finishGitHook(ctx, run, repo.Root) }()
	run.Phase("open_repository")
	repo, err := gitRepo(ctx)
	if run.Check(ctx, err); err != nil {
		return nil
	}
	// Normalizing reads the share URLs in notes; a self-hosted or staging Beacon's links must
	// count as URLs here as they do everywhere else.
	gitAllowShareHosts()
	run.Phase("normalize_notes")
	scanner := bufio.NewScanner(cmd.InOrStdin())
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		if _, err := gitlink.NormalizeNote(ctx, repo.Git, fields[1]); err != nil && ctx.Err() != nil {
			run.Check(ctx, err)
			return nil
		}
	}
	return nil
}

// beaconExecutable is the path hook scripts call first: beacon on PATH when that is this binary
// (a Homebrew symlink survives upgrades; the versioned Cellar path it points to does not), and
// otherwise the running executable.
func beaconExecutable() string {
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	if onPath, err := exec.LookPath("beacon"); err == nil {
		if abs, err := filepath.Abs(onPath); err == nil && sameFile(abs, self) {
			return abs
		}
	}
	return self
}

func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

func init() {
	gitCmd.AddCommand(gitSetupCmd, gitRemoveCmd, gitStatusCmd, gitHookCmd)
	gitHookCmd.AddCommand(gitHookPostCommitCmd, gitHookPostRewriteCmd)
	for _, c := range []*cobra.Command{gitSetupCmd, gitRemoveCmd, gitStatusCmd, gitHookPostCommitCmd, gitHookPostRewriteCmd} {
		c.Flags().StringVarP(&gitOpts.dir, "cwd", "C", "", "Repository to operate on (default the current directory)")
		c.Flags().BoolVar(&gitOpts.jsonOutput, "json", false, "Print the result as JSON")
	}
	gitHookPostCommitCmd.Flags().StringVar(&gitOpts.logPath, "log-path", "", "Runtime JSONL log to read sessions from (default the local runtime log)")
	gitSetupCmd.Flags().BoolVar(&gitSetupOpts.allowHooksPath, "hooks-path", false, "Install into core.hooksPath's directory when it is set")
	gitSetupCmd.Flags().BoolVar(&gitSetupOpts.shareSessions, "share-sessions", false, "Also share the sessions linked to pushed commits to beacon.sh during each git push, and note their links (implies --share-notes; --share-sessions=false turns it off)")
	gitSetupCmd.Flags().StringVar(&gitSetupOpts.shareVisibility, "share-visibility", asymptoteobserve.ShareVisibilityDirect, "With --share-sessions, the visibility of new traces: direct (anyone with the link), private or public")
	gitSetupCmd.Flags().BoolVar(&gitSetupOpts.yes, "yes", false, "With --share-visibility public, set it up without asking")
	gitSetupCmd.Flags().BoolVar(&gitSetupOpts.shareNotes, "share-notes", false, "Share links with remotes: push them with each git push and fetch teammates' (--share-notes=false turns it off)")
}
