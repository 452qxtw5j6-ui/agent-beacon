package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/version"
	observe "github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

// Payload is exactly what Publish sends for one scenario: the PUT body, the events, and
// the external id they are stored under.
type Payload struct {
	ExternalID string                 `json:"external_id"`
	Trace      observe.ShareTraceV1   `json:"trace"`
	Events     []observe.TraceEventV1 `json:"events"`
}

// PayloadOptions shape the published trace.
type PayloadOptions struct {
	Visibility  string
	TitlePrefix string
	// GeneratedAt stamps provenance; zero means the scenario's start, so a payload is
	// byte-for-byte reproducible.
	GeneratedAt time.Time
}

// BuildPayload projects annotated events into the share wire format with the same
// BuildShareBundle the `beacon share` command uses, then marks the trace as generated:
// source "api", provenance source ProvenanceSource, and the title prefix.
func BuildPayload(s *Scenario, events []observe.Event, opts PayloadOptions) Payload {
	at := opts.GeneratedAt
	if at.IsZero() {
		at = s.Start
		if at.IsZero() {
			at = defaultStart
		}
	}
	bundle := observe.BuildShareBundle(events, observe.ShareOptions{
		WorkingDirectory: s.WorkingDirectory(),
		HomeDirectory:    syntheticHome,
		NoHomeLookup:     true,
		BeaconVersion:    version.Version,
		GeneratedAt:      at,
	})
	bundle.Provenance.Source = ProvenanceSource
	trace := observe.NewShareTrace(bundle, opts.Visibility)
	trace.Source = "api"
	trace.Title = observe.ShareTitle(opts.TitlePrefix + s.Title)
	return Payload{
		ExternalID: observe.ShareExternalID(s.Harness, s.SessionID()),
		Trace:      trace,
		Events:     bundle.Events,
	}
}

// PublishResult is what one upload produced.
type PublishResult struct {
	ScenarioID string `json:"scenario_id"`
	ExternalID string `json:"external_id"`
	URL        string `json:"url"`
	Visibility string `json:"visibility"`
	Events     int    `json:"events"`
}

// Publish upserts the payload: PUT the trace, then POST every event. Event ids are
// derived from content, so re-publishing an unchanged scenario rewrites nothing and a
// changed one replaces its events in place. An existing trace keeps the visibility it
// has on beacon.sh unless forceVisibility is set.
func Publish(ctx context.Context, client *account.ShareClient, p Payload, forceVisibility bool) (PublishResult, error) {
	_, found, err := client.GetTrace(ctx, p.ExternalID)
	if err != nil {
		return PublishResult{}, err
	}
	trace := p.Trace
	if found && !forceVisibility {
		trace.Visibility = ""
	}
	put, err := client.PutTrace(ctx, p.ExternalID, trace)
	if err != nil {
		return PublishResult{}, err
	}
	posted, err := client.PostEvents(ctx, p.ExternalID, observe.ShareEventsBatchV1{Events: p.Events})
	if err != nil {
		return PublishResult{}, fmt.Errorf("upload events to %s: %w", put.URL, err)
	}
	count := put.EventCount
	if posted.Batches > 0 {
		count = posted.EventCount
	}
	return PublishResult{ExternalID: p.ExternalID, URL: put.URL, Visibility: put.Visibility, Events: count}, nil
}

// NewClient resolves a credential the way `beacon share` does: --key, then a current
// `beacon login` carrying traces:write, then BEACON_API_KEY.
func NewClient(key, baseURL string, getenv func(string) string) (*account.ShareClient, error) {
	cred, err := account.ResolveShareCredential(account.ResolveShareCredentialOptions{
		Key: strings.TrimSpace(key), BaseURL: baseURL, Getenv: getenv,
	})
	if err != nil {
		return nil, err
	}
	return account.NewShareClient(cred, nil)
}
