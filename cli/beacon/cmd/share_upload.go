package cmd

import (
	"context"
	"fmt"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
)

// shareUploadOptions configures shareUpload.
type shareUploadOptions struct {
	// Visibility is applied when the trace is created; an existing trace keeps its own.
	Visibility string
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
// (alignShareSource) and only the messages after the last one beacon.sh holds are sent
// (messagesAfter), which re-sends open calls and that last message.
func shareUpload(ctx context.Context, client *account.ShareClient, subject shareSubject, opts shareUploadOptions) (shareResult, shareSubject, error) {
	payload, err := buildSharePayload(subject)
	if err != nil {
		return shareResult{}, subject, err
	}
	state, found, err := client.GetTrace(ctx, payload.ExternalID)
	if err != nil {
		return shareResult{}, subject, err
	}
	pending := payload.Messages
	if found {
		if subject, payload, err = alignShareSource(subject, payload, state); err != nil {
			return shareResult{}, subject, err
		}
		payload.Trace.Visibility = ""
		pending = messagesAfter(payload.Messages, state.LastMessageID, state.MaxOrder)
	} else if opts.Visibility != "" {
		payload.Trace.Visibility = opts.Visibility
	}
	trace, err := client.PutTrace(ctx, payload.ExternalID, payload.Trace)
	if err != nil {
		return shareResult{}, subject, err
	}
	uploaded, err := client.PutMessages(ctx, payload.ExternalID, pending)
	if err != nil {
		return shareResult{}, subject, fmt.Errorf("upload messages to %s: %w", trace.URL, err)
	}
	result := shareResult{
		TraceID:      trace.ID,
		ExternalID:   payload.ExternalID,
		SharedURL:    trace.URL,
		Visibility:   trace.Visibility,
		AgentID:      payload.Trace.AgentID,
		MessageCount: trace.MessageCount,
		Uploaded:     len(pending),
		SelectedBy:   subject.selectedBy,
	}
	if found {
		result.MessageCount = state.MessageCount
	}
	if uploaded.Batches > 0 {
		result.MessageCount = uploaded.MessageCount
	}
	if opts.Record {
		if err := recordShareEvent(subject.session, result, found); err != nil {
			return result, subject, &shareRecordError{err: err}
		}
	}
	return result, subject, nil
}
