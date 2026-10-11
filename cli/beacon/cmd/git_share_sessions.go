package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/endpoint/schema"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/gitlink"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/handoff"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// Share URLs in commit notes.
//
// A note line may carry the linked session's shared-trace URL after the link: `beacon:<harness>/<id>
// <url>`. The URL is an identifier like the session id -- it names a page, it carries no content --
// so it belongs in a note that may be pushed. It is only ever an https URL on beacon.sh or on the
// Beacon service this CLI is configured for (gitlink.ValidShareURL); a note can come from anyone
// who pushes to the remote, so any other URL is neither written nor shown.
//
// The post-commit hook takes URLs only from local session.shared events (it never touches the
// network). The pre-push hook, with `beacon git setup --share-sessions`, shares linked sessions
// that have no URL yet during a push the person started, then records the URLs.

const (
	// gitShareMaxSessions bounds how many sessions one push shares.
	gitShareMaxSessions = 10
	// gitShareMaxCommits bounds how many pushed commits are read for links.
	gitShareMaxCommits = 100
	// gitShareNotesReserve is the part of the pre-push budget kept for pushing the notes ref.
	gitShareNotesReserve = 3 * time.Second
	// gitShareNoteWriteBudget is the part kept, after the uploads, for writing the URLs they
	// returned into the local notes. It is local work, so a second is plenty.
	gitShareNoteWriteBudget = time.Second
)

var (
	// gitShareUploadBudget bounds finding and uploading the sessions to share during a push: the
	// pre-push budget less what writing their URLs into the notes and pushing the notes ref need.
	gitShareUploadBudget = gitShareBudget - gitShareNotesReserve - gitShareNoteWriteBudget
	// gitShareUpload is shareUpload; tests replace it.
	gitShareUpload = shareUpload
	// gitShareLogSessions lists the sessions in the runtime log; tests replace it to count reads.
	gitShareLogSessions = func(logPath string) ([]handoff.Session, error) {
		return handoff.LogSessions(logPath, handoff.Filter{})
	}
	// gitShareListStore lists one runtime's stored sessions; tests replace it to count listings.
	gitShareListStore = func(sources []handoff.Source, harness string) ([]handoff.Session, error) {
		return handoff.List(sources, handoff.Filter{Harness: harness, IncludeSubagents: true})
	}
)

// gitShareMaxResolve bounds how many linked sessions without a URL one push looks up, counting the
// ones that are not on this machine (teammates' sessions). Each runtime's store is listed at most
// once per push and the runtime log read at most once, so the cap bounds the per-link work that
// follows (matching, and reading a log session's events), not the number of store listings.
const gitShareMaxResolve = 50

// gitShareStoreIndex finds linked sessions in the runtimes' stores, listing each runtime's store at
// most once per push, on the first link of that runtime. A link names a session by its full id, so
// only an exact, unique id match counts: a prefix match (which handoff.Find would also accept) is
// another session.
type gitShareStoreIndex struct {
	sources []handoff.Source
	byID    map[string]map[string][]handoff.Session // harness -> id -> sessions
}

func newGitShareStoreIndex(sources []handoff.Source) *gitShareStoreIndex {
	return &gitShareStoreIndex{sources: sources, byID: map[string]map[string][]handoff.Session{}}
}

// find returns the stored session of harness with exactly id. ctx is checked before a listing.
func (x *gitShareStoreIndex) find(ctx context.Context, harness, id string) (handoff.Session, bool) {
	index, listed := x.byID[harness]
	if !listed {
		if ctx.Err() != nil {
			return handoff.Session{}, false
		}
		index = map[string][]handoff.Session{}
		// A store that cannot be read lists what it can; the runtime log still answers for it.
		sessions, _ := gitShareListStore(x.sources, harness)
		for _, s := range sessions {
			index[s.ID] = append(index[s.ID], s)
		}
		x.byID[harness] = index
	}
	if matches := index[id]; len(matches) == 1 {
		return matches[0], true
	}
	return handoff.Session{}, false
}

// gitAllowShareHosts admits the configured Beacon service's host besides beacon.sh.
func gitAllowShareHosts() {
	for _, raw := range []string{account.ResolveBaseURL("")} {
		if u, err := url.Parse(raw); err == nil && u.Scheme == "https" {
			gitlink.AllowShareHost(u.Host)
		}
	}
	if session, err := shareAccountLoad(); err == nil && session != nil {
		if u, err := url.Parse(session.BaseURL); err == nil && u.Scheme == "https" {
			gitlink.AllowShareHost(u.Host)
		}
	}
}

func gitShareKey(harness, sessionID string) string {
	name := asymptoteobserve.NormalizeHarnessName(harness)
	if name == "" {
		name = harness
	}
	return name + "/" + sessionID
}

// localShareURLs reads the share URL of every session the runtime log records as shared, from its
// session.shared events, keyed by gitShareKey. Only the current log file is read, and only lines
// that mention the action are decoded, so the post-commit hook stays fast.
func localShareURLs(logPath string) map[string]string {
	urls := map[string]string{}
	f, err := os.Open(logPath)
	if err != nil {
		return urls
	}
	defer f.Close()
	marker := []byte(`"` + SessionSharedAction + `"`)
	reader := bufio.NewReaderSize(f, 256*1024)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 && bytes.Contains(line, marker) {
			var event schema.Event
			if json.Unmarshal(line, &event) == nil && event.Event.Action == SessionSharedAction && event.Session != nil && event.Session.ID != "" {
				if u, _ := event.Raw["shared_url"].(string); gitlink.ValidShareURL(u) {
					urls[gitShareKey(event.Harness.Name, event.Session.ID)] = u
				}
			}
		}
		if err != nil {
			return urls
		}
	}
}

// gitShareURLLookup answers gitlink.Options.ShareURL from the runtime log, read once and only when
// a link is about to be written.
func gitShareURLLookup(logPath string) func(gitlink.Link) string {
	var urls map[string]string
	return func(link gitlink.Link) string {
		if urls == nil {
			gitAllowShareHosts()
			urls = localShareURLs(logPath)
		}
		return urls[gitShareKey(link.Harness, link.SessionID)]
	}
}

// gitPushShareReport is what sharing sessions during one push did.
type gitPushShareReport struct {
	Shared  []string `json:"shared,omitempty"`
	Noted   int      `json:"noted"`
	Skipped string   `json:"skipped,omitempty"`
}

// gitShareSessionsOnPush shares the sessions linked to the commits being pushed that have no share
// URL in their note yet, and writes the URLs into the notes, before the notes ref is pushed. A
// session already shared from this machine only has its URL written. Without a credential it does
// nothing and says nothing. ctx bounds it; every error is returned for one line on stderr, never
// to fail the push.
func gitShareSessionsOnPush(parent context.Context, repo gitlink.Repo, remote, stdin, visibility string) (gitPushShareReport, error) {
	var report gitPushShareReport
	gitAllowShareHosts()
	// The uploads get their own deadline, so running out of it still leaves time to write the URLs
	// of the uploads that did finish; those run on a short context of their own.
	ctx, cancelUploads := context.WithTimeout(parent, gitShareUploadBudget)
	defer cancelUploads()
	commits, err := gitlink.PushedCommits(ctx, repo, remote, stdin, gitShareMaxCommits)
	if err != nil {
		return report, err
	}
	var order []gitlink.Link
	wanted := map[string]bool{}
	notes := map[string]string{}
	for _, sha := range commits {
		note, err := gitlink.ReadNote(ctx, repo.Git, sha)
		if err != nil || note == "" {
			continue
		}
		notes[sha] = note
		for _, link := range gitlink.ParseNote(note) {
			if link.URL == "" && !wanted[link.Key()] {
				wanted[link.Key()] = true
				order = append(order, link)
			}
		}
	}
	if len(order) == 0 {
		return report, nil
	}
	known := localShareURLs(shareLogPath())
	urls := map[string]string{}
	var toShare []gitlink.Link
	for _, link := range order {
		if u := known[gitShareKey(link.Harness, link.SessionID)]; u != "" {
			urls[link.Key()] = u
		} else {
			toShare = append(toShare, link)
		}
	}
	var shareErr error
	type linkedSubject struct {
		link    gitlink.Link
		subject shareSubject
	}
	var subjects []linkedSubject
	if len(toShare) > 0 {
		// Resolve first, cap after: a teammate's session, or one this machine no longer has,
		// must not use up a slot that one of this person's sessions needs. Resolving reads only
		// the local stores, inside the upload budget.
		stores := newGitShareStoreIndex(handoffSources(handoff.StoreDirs{}))
		logPath := shareLogPath()
		var inLog map[string]bool // read once, on the first link the stores do not have
		for i, link := range toShare {
			if ctx.Err() != nil || len(subjects) >= gitShareMaxSessions || i >= gitShareMaxResolve {
				break
			}
			harness, err := handoff.ParseHarness(link.Harness)
			if err != nil {
				continue
			}
			if session, ok := stores.find(ctx, harness, link.SessionID); ok {
				subjects = append(subjects, linkedSubject{link: link, subject: shareSubject{session: session}})
				continue
			}
			if ctx.Err() != nil {
				break
			}
			if inLog == nil {
				inLog = map[string]bool{}
				if sessions, err := gitShareLogSessions(logPath); err == nil {
					for _, s := range sessions {
						inLog[s.Harness+"\x00"+s.ID] = true
					}
				}
			}
			if !inLog[harness+"\x00"+link.SessionID] {
				continue // a teammate's session, or one this machine no longer has
			}
			session, events, found, err := handoff.LogSession(logPath, link.SessionID, harness)
			if err != nil || !found || session.ID != link.SessionID || session.Harness != harness {
				continue
			}
			subjects = append(subjects, linkedSubject{link: link, subject: shareSubject{session: session, fromLog: true, logEvents: events}})
		}
	}
	if len(subjects) > 0 {
		client, err := newShareClient()
		if err != nil {
			report.Skipped = "no Beacon credential"
		} else {
			for _, ls := range subjects {
				if ctx.Err() != nil {
					break
				}
				key := ls.link.Key()
				result, _, err := gitShareUpload(ctx, client, ls.subject, shareUploadOptions{Visibility: visibility, Record: true})
				if err != nil && result.SharedURL == "" {
					if shareErr == nil {
						shareErr = fmt.Errorf("%s: %w", key, err)
					}
					continue
				}
				if gitlink.ValidShareURL(result.SharedURL) {
					urls[key] = result.SharedURL
					report.Shared = append(report.Shared, key)
				}
			}
		}
	}
	if ctx.Err() != nil && shareErr == nil && len(report.Shared) < len(subjects) {
		shareErr = errors.New("ran out of time before every linked session was shared; the next push shares the rest")
	}
	cancelUploads()
	noteCtx, cancelNotes := context.WithTimeout(parent, gitShareNoteWriteBudget)
	defer cancelNotes()
	for sha := range notes {
		changed, err := gitlink.UpdateNote(noteCtx, repo.Git, sha, func(note string) string { return gitlink.SetLinkURLs(note, urls) })
		if err != nil {
			if shareErr == nil {
				shareErr = err
			}
			continue
		}
		if changed {
			report.Noted++
		}
	}
	return report, shareErr
}

// readHookStdin reads what git passes a pre-push hook on stdin, bounded.
func readHookStdin(r io.Reader) string {
	if r == nil {
		return ""
	}
	data, _ := io.ReadAll(io.LimitReader(r, 1<<20))
	return strings.TrimSpace(string(data))
}
