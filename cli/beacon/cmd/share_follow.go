package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
)

// `beacon share --follow` keeps a shared trace current while its session runs: it re-reads the
// session every --interval and uploads what changed, until the session records its end or the
// command is interrupted. Each poll is local; a request is made only when the session's messages
// changed since the last upload, and it goes through shareUpload, the same align-and-resume path
// as `beacon share refresh`.

const (
	shareFollowDefaultInterval = 10 * time.Second
	shareFollowMinInterval     = time.Second
)

var (
	// shareFollowWait sleeps between polls; tests replace it to drive the loop without a clock.
	shareFollowWait = func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
	// shareFollowSignals wires Ctrl+C and SIGTERM to the follow loop's context.
	shareFollowSignals = func(ctx context.Context) (context.Context, context.CancelFunc) {
		return signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	}
)

// shareFollowUpdate is one upload --follow made; --json prints one per line.
type shareFollowUpdate struct {
	shareResult
	Final bool `json:"final,omitempty"`
	// Ended is true when the session recorded its end.
	Ended bool `json:"ended,omitempty"`
}

func runShareFollow(cmd *cobra.Command, client *account.ShareClient, subject shareSubject, visibility string) error {
	interval := shareOpts.interval
	if interval < shareFollowMinInterval {
		interval = shareFollowMinInterval
	}
	ctx, stop := shareFollowSignals(commandContext(cmd))
	defer stop()
	out, errOut := cmd.OutOrStdout(), cmd.ErrOrStderr()
	if !shareOpts.jsonOutput {
		fmt.Fprintf(errOut, "Following %s session %s, uploading new messages every %s. Ctrl+C stops.\n", subject.session.Harness, subject.session.ID, interval)
	}
	var (
		lastPrint string
		last      shareResult
		uploads   int
		ended     bool
	)
	for {
		if subject.fromLog {
			// A session read from the runtime log is re-read each time; one from a store is read
			// fresh by buildSharePayload anyway.
			if fresh, err := resolveShareLog(subject.session); err == nil {
				fresh.selectedBy = subject.selectedBy
				subject = fresh
			}
		}
		fingerprint, end, err := shareFollowState(subject)
		ended = end
		if err == nil && fingerprint != lastPrint {
			opts := shareUploadOptions{Record: uploads == 0}
			if uploads == 0 {
				opts.Visibility = visibility
			}
			result, aligned, upErr := shareUpload(ctx, client, subject, opts)
			switch {
			case upErr == nil:
				subject, last, lastPrint = aligned, result, fingerprint
				uploads++
				if err := printShareFollow(out, errOut, result, uploads == 1, false, ended); err != nil {
					return err
				}
			case ctx.Err() != nil:
				// Interrupted mid-upload; the loop ends below.
			case uploads == 0:
				return upErr
			default:
				// beacon.sh or the network failed after the first upload: say so and retry on the
				// next poll, since the next upload resends whatever this one lacked.
				fmt.Fprintf(errOut, "warning: upload failed, retrying in %s: %v\n", interval, upErr)
			}
		} else if err != nil && uploads == 0 && !errors.Is(err, errShareNothingYet) {
			return err
		}
		if ended || ctx.Err() != nil {
			break
		}
		if shareFollowWait(ctx, interval) != nil {
			break
		}
	}
	if uploads == 0 {
		if ctx.Err() != nil {
			return errors.New("stopped before the session had anything to share")
		}
		return fmt.Errorf("%s session %s has nothing to share", subject.session.Harness, subject.session.ID)
	}
	if uploads > 1 {
		if err := recordShareEvent(subject.session, last, true); err != nil {
			fmt.Fprintf(errOut, "warning: the runtime log was not updated: %v\n", err)
		}
	}
	return printShareFollow(out, errOut, last, false, true, ended)
}

// shareFollowState is a fingerprint of the session's messages as they would be uploaded now, and
// whether the session recorded its end.
func shareFollowState(subject shareSubject) (string, bool, error) {
	_, events, err := shareEvents(subject)
	if err != nil {
		return "", false, err
	}
	ended := false
	for _, e := range events {
		if e.Event.Action == "session.ended" {
			ended = true
		}
	}
	payload, err := buildSharePayload(subject)
	if err != nil {
		return "", ended, err
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", ended, err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), ended, nil
}

func printShareFollow(out, errOut io.Writer, result shareResult, first, final, ended bool) error {
	if shareOpts.jsonOutput {
		return json.NewEncoder(out).Encode(map[string]any{"ok": true, "data": shareFollowUpdate{shareResult: result, Final: final, Ended: ended}})
	}
	switch {
	case first:
		fmt.Fprintln(out, result.SharedURL)
		fmt.Fprintf(errOut, "%s, %d messages. External id: %s\n", result.Visibility, result.MessageCount, result.ExternalID)
	case final && ended:
		fmt.Fprintf(errOut, "The session ended; %s holds %d messages.\n", result.SharedURL, result.MessageCount)
	case final:
		fmt.Fprintf(errOut, "Stopped following; %s holds %d messages.\n", result.SharedURL, result.MessageCount)
	default:
		fmt.Fprintf(errOut, "Uploaded %d message(s); %d in total.\n", result.Uploaded, result.MessageCount)
	}
	return nil
}
