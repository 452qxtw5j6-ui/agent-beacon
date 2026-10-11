package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
)

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
func gitShareSessionsOnPush(ctx context.Context, repo gitlink.Repo, remote, stdin, visibility string) (gitPushShareReport, error) {
	var report gitPushShareReport
	gitAllowShareHosts()
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
	if len(toShare) > gitShareMaxSessions {
		toShare = toShare[:gitShareMaxSessions]
	}
	var shareErr error
	if len(toShare) > 0 {
		client, err := newShareClient()
		if err != nil {
			report.Skipped = "no Beacon credential"
		} else {
			sources := handoffSources(handoff.StoreDirs{})
			for _, link := range toShare {
				if ctx.Err() != nil {
					break
				}
				harness, err := handoff.ParseHarness(link.Harness)
				if err != nil {
					continue
				}
				subject, err := resolveShareID(sources, harness, link.SessionID)
				if err != nil || subject.session.ID != link.SessionID {
					continue // a teammate's session, or one this machine no longer has
				}
				result, _, err := shareUpload(ctx, client, subject, shareUploadOptions{Visibility: visibility, Record: true})
				if err != nil && result.SharedURL == "" {
					if shareErr == nil {
						shareErr = fmt.Errorf("%s: %w", link.Key(), err)
					}
					continue
				}
				if gitlink.ValidShareURL(result.SharedURL) {
					urls[link.Key()] = result.SharedURL
					report.Shared = append(report.Shared, link.Key())
				}
			}
		}
	}
	for sha := range notes {
		changed, err := gitlink.UpdateNote(ctx, repo.Git, sha, func(note string) string { return gitlink.SetLinkURLs(note, urls) })
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
