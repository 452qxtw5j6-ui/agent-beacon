package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/account"
	observe "github.com/asymptote-labs/agent-beacon/pkg/asymptoteobserve"
)

const (
	scenariosDir = "scenarios"
	rulesDir     = "../../../../rules"
)

func loadAll(t *testing.T) []Generated {
	t.Helper()
	scenarios, err := LoadScenarios(scenariosDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarios) == 0 {
		t.Fatal("no scenarios")
	}
	rules, err := LoadRules(rulesDir)
	if err != nil {
		t.Fatal(err)
	}
	var out []Generated
	for _, s := range scenarios {
		g, err := generate(s, rules)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, g)
	}
	return out
}

// Every scenario must keep producing exactly the detections it showcases against the
// rule corpus in this repository, so a rule change that stops catching one fails here.
func TestScenariosTriggerTheirExpectedRules(t *testing.T) {
	for _, g := range loadAll(t) {
		if g.Err != nil {
			t.Error(g.Err)
		}
	}
}

func TestEveryFindingBecomesAPolicyLine(t *testing.T) {
	for _, g := range loadAll(t) {
		p := BuildPayload(g.Scenario, g.Events, PayloadOptions{Visibility: observe.ShareVisibilityDirect, TitlePrefix: defaultTitlePrefix})
		detected := map[string]bool{}
		for _, e := range p.Events {
			if e.Action == "policy.detected" && e.Policy != nil {
				detected[e.Policy.ID] = true
				if e.Fidelity != observe.FidelityInferred {
					t.Errorf("%s: detection %s is %q, want inferred", g.Scenario.ID, e.Policy.ID, e.Fidelity)
				}
			}
		}
		for _, f := range g.Findings {
			if !detected[f.RuleID] {
				t.Errorf("%s: finding %s has no policy.detected event in the payload", g.Scenario.ID, f.RuleID)
			}
		}
		var lines int
		for _, m := range observe.TraceMessages(observe.TraceBundleV1{Events: p.Events}) {
			for _, part := range m.Parts {
				if content, ok := part.Content.(map[string]interface{}); ok && content["subtype"] == "policy" {
					lines++
				}
			}
		}
		if lines != len(g.Findings) {
			t.Errorf("%s: chat view has %d policy lines, want %d", g.Scenario.ID, lines, len(g.Findings))
		}
	}
}

// The payload is what goes public: it must be reproducible, marked as generated, and
// free of the synthetic home (the share scrubber rewrites it like a real one).
func TestPayloadIsMarkedReproducibleAndScrubbed(t *testing.T) {
	for _, g := range loadAll(t) {
		opts := PayloadOptions{Visibility: observe.ShareVisibilityDirect, TitlePrefix: defaultTitlePrefix}
		a, _ := json.Marshal(BuildPayload(g.Scenario, g.Events, opts))
		b, _ := json.Marshal(BuildPayload(g.Scenario, g.Events, opts))
		if !bytes.Equal(a, b) {
			t.Errorf("%s: payload is not deterministic", g.Scenario.ID)
		}
		p := BuildPayload(g.Scenario, g.Events, opts)
		if !strings.HasPrefix(p.Trace.Title, defaultTitlePrefix) {
			t.Errorf("%s: title %q lacks the simulated prefix", g.Scenario.ID, p.Trace.Title)
		}
		if p.Trace.Provenance.Source != ProvenanceSource || p.Trace.Source != "api" {
			t.Errorf("%s: provenance %q source %q", g.Scenario.ID, p.Trace.Provenance.Source, p.Trace.Source)
		}
		if strings.Contains(string(a), syntheticHome) {
			t.Errorf("%s: payload still contains %s", g.Scenario.ID, syntheticHome)
		}
		if !observe.ValidShareExternalID(p.ExternalID) {
			t.Errorf("%s: invalid external id %q", g.Scenario.ID, p.ExternalID)
		}
	}
}

func TestPublishUpsertsTraceAndEvents(t *testing.T) {
	var mu sync.Mutex
	var puts []observe.ShareTraceV1
	var events int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer bcn_api_test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body := io.Reader(r.Body)
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			body = zr
		}
		switch {
		case r.Method == http.MethodGet:
			http.NotFound(w, r)
		case r.Method == http.MethodPut:
			var trace observe.ShareTraceV1
			_ = json.NewDecoder(body).Decode(&trace)
			puts = append(puts, trace)
			_ = json.NewEncoder(w).Encode(observe.ShareTraceResultV1{ID: "t1", URL: "https://beacon.example/s/t1", Visibility: trace.Visibility, Created: true})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/events/batch"):
			var batch observe.ShareEventsBatchV1
			_ = json.NewDecoder(body).Decode(&batch)
			events += len(batch.Events)
			_ = json.NewEncoder(w).Encode(observe.ShareBatchResultV1{Upserted: len(batch.Events), EventCount: events})
		default:
			http.Error(w, "unexpected "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client, err := account.NewShareClient(account.ShareCredential{BaseURL: srv.URL, Token: "bcn_api_test", Source: account.CredentialSourceFlag}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	g := loadAll(t)[0]
	p := BuildPayload(g.Scenario, g.Events, PayloadOptions{Visibility: observe.ShareVisibilityDirect, TitlePrefix: defaultTitlePrefix})
	res, err := Publish(context.Background(), client, p, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.URL == "" || res.Events != len(p.Events) || len(puts) != 1 || puts[0].Visibility != observe.ShareVisibilityDirect {
		t.Fatalf("result %+v, puts %d, events %d", res, len(puts), events)
	}
}

func TestPublicPublishNeedsConfirmation(t *testing.T) {
	err := run([]string{"publish", "-scenarios", scenariosDir, "-rules", rulesDir, "-visibility", "public"}, io.Discard, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "-yes") {
		t.Fatalf("err = %v, want a refusal naming -yes", err)
	}
}

func TestBuildWritesScannableJSONL(t *testing.T) {
	out := t.TempDir()
	if err := run([]string{"build", "-scenarios", scenariosDir, "-rules", rulesDir, "-out", out}, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	for _, g := range loadAll(t) {
		for _, name := range []string{"runtime.jsonl", "findings.json", "payload.json"} {
			if _, err := os.Stat(filepath.Join(out, g.Scenario.ID, name)); err != nil {
				t.Error(err)
			}
		}
	}
}

func TestScenarioValidation(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad-one.yaml")
	if err := os.WriteFile(bad, []byte(`id: bad-one
title: t
vulnerability: {class: c}
harness: claude_code
project: p
expect: {rules: [x]}
steps:
  - prompt: hi
  - agent: a
    command: {command: ls}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadScenario(bad); err == nil || !strings.Contains(err.Error(), "exactly one kind") {
		t.Fatalf("err = %v", err)
	}
}
