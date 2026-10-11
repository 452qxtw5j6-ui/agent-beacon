package asymptoteobserve

import "testing"

// Trace usage carries the one-hour cache-write subset beside the write count, clamped to it, and
// sums it with the writes it belongs to.
func TestTraceUsageCarriesTheOneHourCacheWriteSubset(t *testing.T) {
	event := func(total, oneHour int64) Event {
		claimed := oneHour
		return Event{GenAI: &GenAIInfo{Usage: &GenAIUsageInfo{
			CacheCreation: &GenAIUsageCacheCreationInfo{InputTokens: &total, Ephemeral1hInputTokens: &claimed},
		}}}
	}
	first := traceUsage(event(20000, 16000))
	if first == nil || first.CacheCreationInputTokens != 20000 || first.CacheCreation1hInputTokens != 16000 {
		t.Fatalf("usage = %+v, want 20000 writes of which 16000 one-hour", first)
	}
	// A log line claiming more one-hour writes than writes is clamped.
	second := traceUsage(event(500, 900))
	if second == nil || second.CacheCreation1hInputTokens != 500 {
		t.Fatalf("usage = %+v, want the subset clamped to 500", second)
	}
	sum := TraceUsageV1{}
	AddTraceUsage(&sum, *first)
	AddTraceUsage(&sum, *second)
	if sum.CacheCreationInputTokens != 20500 || sum.CacheCreation1hInputTokens != 16500 {
		t.Fatalf("sum = %+v", sum)
	}
	unsplit := traceUsage(Event{GenAI: &GenAIInfo{Usage: &GenAIUsageInfo{
		CacheCreation: NewCacheCreationUsage(300, nil),
	}}})
	if unsplit == nil || unsplit.CacheCreation1hInputTokens != 0 {
		t.Fatalf("usage = %+v, want no subset when unreported", unsplit)
	}
}
