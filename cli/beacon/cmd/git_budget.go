package cmd

import (
	"context"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/diagnostics"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/writer"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/gitlink"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/version"
)

// gitOverrunWindow is how far back `beacon git status` and `beacon endpoint doctor` count git hook
// runs that ran out of time.
const gitOverrunWindow = 7 * 24 * time.Hour

// startGitHook begins measuring one run of a git hook and returns the hook's context: bounded by
// budget, and counting every git process started under it. Tests replace it to pin the clock and
// end the hook's time in a chosen phase without waiting for a real deadline.
var startGitHook = func(parent context.Context, hook string, budget time.Duration) (*gitlink.HookRun, context.Context, context.CancelFunc) {
	run := &gitlink.HookRun{Hook: hook, Budget: budget}
	ctx, cancel := context.WithTimeout(parent, budget)
	return run, run.Start(ctx), cancel
}

// finishGitHook records the run in the runtime log when it ran out of time: one
// git.hook_budget_exceeded event, through the writer the link events use, and nothing on the
// terminal. ctx is the hook's own context, so a deadline that passed after the last step counts
// too, as a run that finished late. It spawns no git and makes no network request; a log the hook
// cannot write loses only the record.
func finishGitHook(ctx context.Context, run *gitlink.HookRun, repoRoot string) {
	run.Check(ctx, nil)
	if event, ok := run.Event(repoRoot, version.GetVersion()); ok {
		_, _ = writer.AppendEvent(event, writer.Options{Path: gitRuntimeLogPath(), UserMode: true})
	}
}

// gitHookBudgetCheck is doctor's view of the git hook runs that ran out of time in the last week,
// across every repository. It appears only when there were some, so an endpoint whose hooks fit
// their budget (or that never installed them) sees no new line. A run cut short warns: it is a
// commit left unlinked, or a link event, note or share left unrecorded. Runs that only finished
// late are reported as ok, because nothing was lost.
func gitHookBudgetCheck(logPath string, now time.Time) (diagnostics.Check, bool) {
	overruns := gitlink.ScanBudgetOverruns(logPath, "", now.Add(-gitOverrunWindow))
	if overruns.Last == nil {
		return diagnostics.Check{}, false
	}
	check := diagnostics.Check{
		Name:     "git_hook_budget",
		Target:   overruns.Last.Repository,
		Status:   diagnostics.StatusOK,
		Severity: diagnostics.SeverityInfo,
		Message:  describeGitOverruns(overruns),
		Evidence: "git_hook_finished_late",
	}
	if overruns.CutShort > 0 {
		check.Status = diagnostics.StatusWarn
		check.Severity = diagnostics.SeverityLow
		check.Evidence = "git_hook_cut_short"
		check.Action = "run `beacon git status` in the repository to see its overruns, and `beacon git link <commit>` to link a commit the hook left unlinked"
	}
	return check, true
}
