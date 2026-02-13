// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package metrics

import (
	"testing"
	"time"

	"github.com/mbeema/olly/pkg/traces"
)

func TestGenAIMetricsRecordAndCollect(t *testing.T) {
	gm := NewGenAIMetrics(nil) // default buckets

	span := &traces.Span{
		Protocol:    "genai",
		ServiceName: "my-app",
		Duration:    2 * time.Second,
		Attributes: map[string]string{
			"gen_ai.system":              "openai",
			"gen_ai.request.model":       "gpt-4o",
			"gen_ai.response.model":      "gpt-4o-2024-08-06",
			"gen_ai.usage.input_tokens":  "25",
			"gen_ai.usage.output_tokens": "100",
		},
	}

	gm.RecordSpan(span)

	now := time.Now()
	metrics := gm.Collect(now)

	if len(metrics) == 0 {
		t.Fatal("expected metrics, got none")
	}

	// Should have: input tokens, output tokens, duration histogram
	var foundInputTokens, foundOutputTokens, foundDuration bool
	for _, m := range metrics {
		switch m.Name {
		case "gen_ai.client.token.usage":
			if m.Labels["gen_ai.token.type"] == "input" {
				foundInputTokens = true
				if m.Value != 25 {
					t.Errorf("input token value = %f, want 25", m.Value)
				}
				if m.Labels["gen_ai.system"] != "openai" {
					t.Errorf("provider label = %q, want openai", m.Labels["gen_ai.system"])
				}
				if m.Labels["gen_ai.response.model"] != "gpt-4o-2024-08-06" {
					t.Errorf("model label = %q, want gpt-4o-2024-08-06", m.Labels["gen_ai.response.model"])
				}
			} else if m.Labels["gen_ai.token.type"] == "output" {
				foundOutputTokens = true
				if m.Value != 100 {
					t.Errorf("output token value = %f, want 100", m.Value)
				}
			}
		case "gen_ai.client.operation.duration":
			foundDuration = true
			if m.Histogram == nil {
				t.Error("duration metric should have histogram data")
			} else {
				if m.Histogram.Count != 1 {
					t.Errorf("histogram count = %d, want 1", m.Histogram.Count)
				}
				if m.Histogram.Sum != 2.0 {
					t.Errorf("histogram sum = %f, want 2.0", m.Histogram.Sum)
				}
			}
		}
	}

	if !foundInputTokens {
		t.Error("missing input token metric")
	}
	if !foundOutputTokens {
		t.Error("missing output token metric")
	}
	if !foundDuration {
		t.Error("missing duration metric")
	}
}

func TestGenAIMetricsSkipNonGenAI(t *testing.T) {
	gm := NewGenAIMetrics(nil)

	span := &traces.Span{
		Protocol: "http",
		Duration: time.Second,
		Attributes: map[string]string{
			"http.request.method": "GET",
		},
	}

	gm.RecordSpan(span)

	metrics := gm.Collect(time.Now())
	if len(metrics) != 0 {
		t.Errorf("expected no metrics for non-genai span, got %d", len(metrics))
	}
}

func TestGenAIMetricsMultipleModels(t *testing.T) {
	gm := NewGenAIMetrics(nil)

	// Record spans for two different models
	gm.RecordSpan(&traces.Span{
		Protocol:    "genai",
		ServiceName: "app",
		Duration:    time.Second,
		Attributes: map[string]string{
			"gen_ai.system":              "openai",
			"gen_ai.response.model":      "gpt-4o",
			"gen_ai.usage.input_tokens":  "10",
			"gen_ai.usage.output_tokens": "20",
		},
	})

	gm.RecordSpan(&traces.Span{
		Protocol:    "genai",
		ServiceName: "app",
		Duration:    3 * time.Second,
		Attributes: map[string]string{
			"gen_ai.system":              "anthropic",
			"gen_ai.response.model":      "claude-3-5-sonnet",
			"gen_ai.usage.input_tokens":  "50",
			"gen_ai.usage.output_tokens": "200",
		},
	})

	metrics := gm.Collect(time.Now())

	// Should have metrics for both models: 2 token types each + 1 duration each = 6
	if len(metrics) < 4 {
		t.Errorf("expected at least 4 metrics for 2 models, got %d", len(metrics))
	}

	// Verify models are tracked separately
	modelCounts := map[string]int{}
	for _, m := range metrics {
		model := m.Labels["gen_ai.response.model"]
		modelCounts[model]++
	}
	if modelCounts["gpt-4o"] < 2 { // input tokens + output tokens + duration
		t.Errorf("gpt-4o metric count = %d, want >= 2", modelCounts["gpt-4o"])
	}
	if modelCounts["claude-3-5-sonnet"] < 2 {
		t.Errorf("claude-3-5-sonnet metric count = %d, want >= 2", modelCounts["claude-3-5-sonnet"])
	}
}

func TestGenAIMetricsNoTokens(t *testing.T) {
	gm := NewGenAIMetrics(nil)

	// Span with no token info (e.g., streaming or truncated)
	gm.RecordSpan(&traces.Span{
		Protocol: "genai",
		Duration: 5 * time.Second,
		Attributes: map[string]string{
			"gen_ai.system":         "openai",
			"gen_ai.response.model": "gpt-4o",
		},
	})

	metrics := gm.Collect(time.Now())

	// Should only have duration metric (no token metrics)
	for _, m := range metrics {
		if m.Name == "gen_ai.client.token.usage" {
			t.Error("should not have token metrics when tokens are not reported")
		}
	}

	// Duration should still be present
	foundDuration := false
	for _, m := range metrics {
		if m.Name == "gen_ai.client.operation.duration" {
			foundDuration = true
		}
	}
	if !foundDuration {
		t.Error("expected duration metric even without token data")
	}
}

func TestGenAIMetricsDurationBuckets(t *testing.T) {
	buckets := []float64{1, 5, 10}
	gm := NewGenAIMetrics(buckets)

	// Record spans at different durations
	for _, d := range []time.Duration{
		500 * time.Millisecond, // bucket 0 (<=1s)
		3 * time.Second,       // bucket 1 (<=5s)
		7 * time.Second,       // bucket 2 (<=10s)
		15 * time.Second,      // overflow
	} {
		gm.RecordSpan(&traces.Span{
			Protocol: "genai",
			Duration: d,
			Attributes: map[string]string{
				"gen_ai.system":         "openai",
				"gen_ai.response.model": "gpt-4o",
			},
		})
	}

	metrics := gm.Collect(time.Now())

	for _, m := range metrics {
		if m.Name == "gen_ai.client.operation.duration" && m.Histogram != nil {
			if m.Histogram.Count != 4 {
				t.Errorf("histogram count = %d, want 4", m.Histogram.Count)
			}
			// Cumulative: bucket[0]=1, bucket[1]=2, bucket[2]=3
			if len(m.Histogram.Buckets) != 3 {
				t.Fatalf("bucket count = %d, want 3", len(m.Histogram.Buckets))
			}
			if m.Histogram.Buckets[0].Count != 1 {
				t.Errorf("bucket[0] count = %d, want 1", m.Histogram.Buckets[0].Count)
			}
			if m.Histogram.Buckets[1].Count != 2 {
				t.Errorf("bucket[1] count = %d, want 2", m.Histogram.Buckets[1].Count)
			}
			if m.Histogram.Buckets[2].Count != 3 {
				t.Errorf("bucket[2] count = %d, want 3", m.Histogram.Buckets[2].Count)
			}
		}
	}
}

func TestGenAIMetricsFallbackToRequestModel(t *testing.T) {
	gm := NewGenAIMetrics(nil)

	// Only request model set (no response model)
	gm.RecordSpan(&traces.Span{
		Protocol: "genai",
		Duration: time.Second,
		Attributes: map[string]string{
			"gen_ai.system":              "openai",
			"gen_ai.request.model":       "gpt-4o",
			"gen_ai.usage.input_tokens":  "10",
		},
	})

	metrics := gm.Collect(time.Now())
	foundModel := false
	for _, m := range metrics {
		if m.Labels["gen_ai.response.model"] == "gpt-4o" {
			foundModel = true
		}
	}
	if !foundModel {
		t.Error("expected fallback to request model in labels")
	}
}
