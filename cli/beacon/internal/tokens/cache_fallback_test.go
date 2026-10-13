package tokens

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/asymptote-labs/agent-beacon/cli/beacon/internal/pricing"
)

func TestOneHourOverrideFallbacksInReportJSON(t *testing.T) {
	for _, tc := range []struct {
		name, extraRate string
		oneHour         int64
		wantCost        float64
		wantFallbacks   []string
	}{
		{"explicit_one_hour", `,"cache_write_1h_usd_per_mtok":5`, 1000, 0.005, nil},
		{"mixed_ttls", `,"cache_write_1h_usd_per_mtok":5`, 600, 0.0038, []string{"cache_write_at_input_rate"}},
		{"both_rates_missing", "", 1000, 0.002, []string{"cache_write_1h_at_write_rate", "cache_write_at_input_rate"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := pricing.Default()
			overrides, err := pricing.LoadOverrides([]byte(`{"schema":"beacon.pricing.overrides/v1","models":{"internal-model":{"input_usd_per_mtok":2,"output_usd_per_mtok":3`+tc.extraRate+`}}}`), catalog)
			if err != nil {
				t.Fatal(err)
			}
			line := `{"timestamp":"2026-10-12T10:00:00Z","event":{"kind":"agent_runtime","action":"token.usage","category":"metric"},"harness":{"name":"claude_code","collection_method":"poll"},"session":{"id":"s1"},"model":"internal-model","gen_ai":{"usage":{"cache_creation":{"input_tokens":1000,"ephemeral_1h_input_tokens":`
			subset, _ := json.Marshal(tc.oneHour)
			report := Aggregate(decodeEvents(t, line+string(subset)+`}}}}`), Options{Pricer: pricing.NewPricer(catalog, overrides)})
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			var wire struct {
				Pricing struct {
					Models []struct {
						Fallbacks        []string `json:"fallbacks"`
						EstimatedCostUSD float64  `json:"estimated_cost_usd"`
					} `json:"models"`
				} `json:"pricing"`
			}
			if err := json.Unmarshal(encoded, &wire); err != nil {
				t.Fatal(err)
			}
			if len(wire.Pricing.Models) != 1 {
				t.Fatalf("report JSON = %s", encoded)
			}
			got := wire.Pricing.Models[0]
			if got.EstimatedCostUSD != tc.wantCost || !reflect.DeepEqual(got.Fallbacks, tc.wantFallbacks) {
				t.Fatalf("report pricing = %+v; want cost %v fallbacks %v", got, tc.wantCost, tc.wantFallbacks)
			}
		})
	}
}
