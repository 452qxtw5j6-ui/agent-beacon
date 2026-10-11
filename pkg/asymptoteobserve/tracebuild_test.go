package asymptoteobserve

import (
	"encoding/json"
	"reflect"
	"testing"
)

func traceTestEvents() []Event {
	start := shareEventAt("2026-10-01T10:00:00Z", "claude", CollectionMethodHook, "session.started", "session")
	start.Event.ID = "t-start"
	start.Message = "Claude Code session started"
	start.Trace = &TraceInfo{ID: "abc", SpanID: "root"}
	prompt := shareEventAt("2026-10-01T10:00:01Z", "claude", CollectionMethodHook, "prompt.submitted", "prompt")
	prompt.Prompt = &PromptInfo{ID: " p-1 ", Text: "explain the cache"}
	prompt.Content = &ContentInfo{Retention: "full", Included: true}
	prompt.Trace = &TraceInfo{ID: "abc", SpanID: "child", ParentSpanID: "root"}
	reply := shareEventAt("2026-10-01T10:00:02Z", "opencode", CollectionMethodPlugin, "agent.response", "session")
	reply.Event.ID = "t-reply"
	reply.Message = "opencode assistant response captured"
	reply.Model = "claude-sonnet-5-5"
	reply.GenAI = &GenAIInfo{Output: &GenAIOutputInfo{Messages: TextOutputMessages("It memoizes lookups.")},
		Usage: &GenAIUsageInfo{InputTokens: int64Ptr(10), OutputTokens: int64Ptr(4)}}
	reply.Content = &ContentInfo{Retention: "full", Included: true, Redacted: true}
	reply.Branch = "main"
	reply.Raw = map[string]interface{}{"namespace_slug": "acme", "remote_event_count": float64(9)}
	return []Event{start, prompt, reply}
}

func TestTraceEventFromEvent(t *testing.T) {
	events := traceTestEvents()
	te := TraceEventFromEvent(events[1], "line-7", 3)
	if te.ID != "line-7" || te.SourceEventID != "line-7" || te.Number != 3 {
		t.Fatalf("identity = %+v", te)
	}
	if te.Type != "user_message" || te.Actor != "user" || te.PromptID != "p-1" || te.Content == nil || te.Content.Text != "explain the cache" {
		t.Fatalf("prompt = %+v", te)
	}
	if te.Trace == nil || te.Trace.SpanID != "child" || te.Trace.ParentSpanID != "root" {
		t.Fatalf("trace = %+v", te.Trace)
	}
	// OpenCode records the assistant's text as agent.response.
	reply := TraceEventFromEvent(events[2], "", 1)
	if reply.ID != "t-reply" || reply.Type != "agent_message" || reply.Actor != "assistant" || reply.Content.Text != "It memoizes lookups." || reply.Summary != "opencode assistant response captured" {
		t.Fatalf("reply = %+v", reply)
	}
	if reply.Usage == nil || reply.Usage.InputTokens != 10 || reply.Model != "claude-sonnet-5-5" {
		t.Fatalf("usage = %+v, model = %q", reply.Usage, reply.Model)
	}
}

func TestNormalizeTraceEvent(t *testing.T) {
	metric := Event{Raw: map[string]interface{}{"metric_name": "claude_code.cost.usage"}}
	NormalizeTraceEvent(&metric)
	if metric.Event.Category != "metric" || metric.Event.Action != "claude_code.cost.usage" {
		t.Fatalf("metric = %+v", metric.Event)
	}
	file := Event{Event: EventInfo{Action: "file.read"}}
	NormalizeTraceEvent(&file)
	if file.Event.Category != "file" {
		t.Fatalf("category = %q", file.Event.Category)
	}
}

func TestTraceBuilderFoldsASummary(t *testing.T) {
	events := traceTestEvents()
	b := NewTraceBuilder("trace:abc", events[0])
	for i, event := range events {
		b.Add(event, TraceEventFromEvent(event, "line", i+10))
	}
	summary := b.Summary()
	if len(b.Events()) != 3 || b.Events()[2].Number != 3 {
		t.Fatalf("events = %+v", b.Events())
	}
	// The lifecycle event opens the trace, the prompt names it.
	if summary.Title != "explain the cache" || summary.Preview != "explain the cache" {
		t.Fatalf("title = %q, preview = %q", summary.Title, summary.Preview)
	}
	if summary.EventCount != 3 || summary.LocalMessageCount != 2 || summary.StartedAt != "2026-10-01T10:00:00Z" || summary.EndedAt != "2026-10-01T10:00:02Z" {
		t.Fatalf("counts = %+v", summary)
	}
	if summary.Trace == nil || summary.Trace.ID != "abc" || summary.Trace.RootSpanID != "root" {
		t.Fatalf("trace = %+v", summary.Trace)
	}
	if !reflect.DeepEqual(summary.Harness.CollectionMethods, []string{"hook", "plugin"}) || summary.Model == nil || summary.Model.Primary != "claude-sonnet-5-5" {
		t.Fatalf("harness = %+v, model = %+v", summary.Harness, summary.Model)
	}
	if summary.TokenUsage == nil || *summary.TokenUsage != (TraceUsageV1{InputTokens: 10, OutputTokens: 4}) {
		t.Fatalf("usage = %+v", summary.TokenUsage)
	}
	if summary.Repository == nil || summary.Repository.Branch != "main" || summary.Namespace == nil || summary.Namespace.Slug != "acme" {
		t.Fatalf("repository = %+v, namespace = %+v", summary.Repository, summary.Namespace)
	}
	if summary.Content.Retention != "full" || !summary.Content.HasRedactions {
		t.Fatalf("content = %+v", summary.Content)
	}
	// Nine remote events against three local ones: the share is behind.
	if summary.RemoteEventCount != 9 || summary.SharedEventCount != 9 || summary.Sharing.State != "stale" {
		t.Fatalf("sharing = %+v remote %d shared %d", summary.Sharing, summary.RemoteEventCount, summary.SharedEventCount)
	}
	// Summary does not change the builder.
	if again := b.Summary(); !reflect.DeepEqual(again, summary) {
		t.Fatalf("summary changed on a second read:\n%+v\n%+v", again, summary)
	}

	bundle := b.Bundle(TraceProvenanceV1{Source: "test"})
	if bundle.SchemaVersion != TraceSchemaVersion || bundle.ID != "trace:abc" || len(bundle.Events) != 3 || bundle.Range == nil || bundle.Range.TotalEvents != 3 {
		t.Fatalf("bundle = %+v", bundle)
	}
	if len(bundle.Spans) != 2 || bundle.Spans[0].ID != "child" || bundle.Spans[1].ID != "root" || bundle.Spans[1].Name != "Claude Code session started" {
		t.Fatalf("spans = %+v", bundle.Spans)
	}
}

// A builder restored from its saved state continues exactly as one that never stopped, which is
// what the dashboard's history relies on.
func TestTraceBuilderStateRoundTrip(t *testing.T) {
	events := traceTestEvents()
	whole := NewTraceBuilder("trace:abc", events[0])
	for i, event := range events {
		whole.Fold(event, TraceEventFromEvent(event, "", i+1))
	}
	first := NewTraceBuilder("trace:abc", events[0])
	first.Fold(events[0], TraceEventFromEvent(events[0], "", 1))
	data, err := json.Marshal(first.State())
	if err != nil {
		t.Fatal(err)
	}
	var state TraceBuilderState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	rest := RestoreTraceBuilder(state)
	for i, event := range events[1:] {
		rest.Fold(event, TraceEventFromEvent(event, "", i+2))
	}
	got, _ := json.Marshal(rest.Summary())
	want, _ := json.Marshal(whole.Summary())
	if string(got) != string(want) {
		t.Fatalf("restored summary differs:\n%s\n%s", got, want)
	}
	if len(rest.Events()) != 0 {
		t.Fatal("Fold kept events")
	}
}
