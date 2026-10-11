package cmd

import (
	"context"
	"fmt"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
	"github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// shareUploadOptions configures shareUpload.
type shareUploadOptions struct {
	// Visibility is applied when the trace is created. An existing trace keeps its own unless
	// ExplicitVisibility says the person asked for this one (--visibility), as plain share does.
	Visibility         string
	ExplicitVisibility bool
	// ExplicitTitle keeps the payload's title for an existing trace (--title). Otherwise an
	// existing trace keeps its title, so a --title or a rename on beacon.sh is not replaced by the
	// derived one (keepSharedTitle).
	ExplicitTitle bool
	// Record writes the session.shared event after the upload.
	Record bool
}

// shareRecordError is shareUpload's error when the upload succeeded and only writing the
// session.shared event failed; the result it returns with it is the upload's.
type shareRecordError struct{ err error }

func (e *shareRecordError) Error() string {
	return "shared, but the runtime log was not updated: " + e.err.Error()
}

func (e *shareRecordError) Unwrap() error { return e.err }

// shareUpload creates or updates subject's shared trace, sending only what beacon.sh lacks. It is
// the path every non-interactive upload takes (the pre-push hook, --follow), so it applies the same
// rules as `beacon share refresh`: an existing trace is checked against this copy of the session
// (alignShareSource) and only the events after the last one beacon.sh holds are sent
// (ShareEventsAfter), which re-sends that last event and any tool call still open.
func shareUpload(ctx context.Context, client *account.ShareClient, subject shareSubject, opts shareUploadOptions) (shareResult, shareSubject, error) {
	readAt := shareNow()
	payload, err := buildSharePayload(subject)
	if err != nil {
		return shareResult{}, subject, err
	}
	state, found, err := client.GetTrace(ctx, payload.ExternalID)
	if err != nil {
		return shareResult{}, subject, err
	}
	pending := payload.Events
	if found {
		if subject, payload, err = alignShareSource(subject, payload, state); err != nil {
			return shareResult{}, subject, err
		}
		if opts.ExplicitVisibility && opts.Visibility != "" {
			payload.Trace.Visibility = opts.Visibility
		} else {
			payload.Trace.Visibility = ""
		}
		if !opts.ExplicitTitle {
			payload.Trace.Title = ""
		}
		pending = asymptoteobserve.ShareEventsAfter(payload.Events, state.LastEventID, state.MaxNumber)
	} else if opts.Visibility != "" {
		payload.Trace.Visibility = opts.Visibility
	}
	trace, err := client.PutTrace(ctx, payload.ExternalID, payload.Trace)
	if err != nil {
		return shareResult{}, subject, err
	}
	uploaded, err := client.PostEvents(ctx, payload.ExternalID, asymptoteobserve.ShareEventsBatchV1{Events: pending})
	if err != nil {
		return shareResult{}, subject, fmt.Errorf("upload events to %s: %w", trace.URL, err)
	}
	result := shareResult{
		TraceID:       trace.ID,
		ExternalID:    payload.ExternalID,
		SharedURL:     trace.URL,
		Visibility:    trace.Visibility,
		Harness:       payload.harness(),
		EventCount:    trace.EventCount,
		Uploaded:      len(pending),
		SelectedBy:    subject.selectedBy,
		SharedThrough: readAt,
	}
	if found {
		result.EventCount = state.EventCount
		result.sharedAt = state.CreatedAt
	}
	if uploaded.Batches > 0 {
		result.EventCount = uploaded.EventCount
	}
	if opts.Record {
		if err := recordShareEvent(subject.session, result, found); err != nil {
			return result, subject, &shareRecordError{err: err}
		}
	}
	return result, subject, nil
}
