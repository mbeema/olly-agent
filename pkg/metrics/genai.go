// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package metrics

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mbeema/olly/pkg/traces"
)

// DefaultGenAIBuckets are the default duration histogram buckets for GenAI operations.
// LLM calls are slower than typical HTTP, so buckets extend to 120 seconds.
var DefaultGenAIBuckets = []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

// GenAIMetrics tracks token usage and operation duration per model.
type GenAIMetrics struct {
	mu      sync.RWMutex
	models  map[genaiModelKey]*genaiModelMetrics
	buckets []float64
}

// genaiModelKey identifies a unique model for metric aggregation.
type genaiModelKey struct {
	Service  string
	Provider string
	Model    string
}

type genaiModelMetrics struct {
	inputTokens     atomic.Uint64
	outputTokens    atomic.Uint64
	requestCount    atomic.Uint64
	durationSumNs   atomic.Int64
	durationBuckets []atomic.Uint64
	overflowCount   atomic.Uint64
}

// NewGenAIMetrics creates a new GenAI metrics tracker.
func NewGenAIMetrics(buckets []float64) *GenAIMetrics {
	if len(buckets) == 0 {
		buckets = DefaultGenAIBuckets
	}
	return &GenAIMetrics{
		models:  make(map[genaiModelKey]*genaiModelMetrics),
		buckets: buckets,
	}
}

// RecordSpan records metrics from a completed GenAI span.
func (g *GenAIMetrics) RecordSpan(span *traces.Span) {
	if span.Protocol != "genai" {
		return
	}

	provider := span.Attributes["gen_ai.system"]
	model := span.Attributes["gen_ai.response.model"]
	if model == "" {
		model = span.Attributes["gen_ai.request.model"]
	}

	key := genaiModelKey{
		Service:  span.ServiceName,
		Provider: provider,
		Model:    model,
	}

	mm := g.getOrCreate(key)
	mm.requestCount.Add(1)

	// Record token usage
	if v, ok := span.Attributes["gen_ai.usage.input_tokens"]; ok {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			mm.inputTokens.Add(n)
		}
	}
	if v, ok := span.Attributes["gen_ai.usage.output_tokens"]; ok {
		if n, err := strconv.ParseUint(v, 10, 64); err == nil {
			mm.outputTokens.Add(n)
		}
	}

	// Record duration
	durationSec := span.Duration.Seconds()
	mm.durationSumNs.Add(span.Duration.Nanoseconds())

	placed := false
	for i, bound := range g.buckets {
		if durationSec <= bound {
			mm.durationBuckets[i].Add(1)
			placed = true
			break
		}
	}
	if !placed {
		mm.overflowCount.Add(1)
	}
}

func (g *GenAIMetrics) getOrCreate(key genaiModelKey) *genaiModelMetrics {
	g.mu.RLock()
	mm, ok := g.models[key]
	g.mu.RUnlock()
	if ok {
		return mm
	}

	g.mu.Lock()
	if mm, ok = g.models[key]; ok {
		g.mu.Unlock()
		return mm
	}
	mm = &genaiModelMetrics{
		durationBuckets: make([]atomic.Uint64, len(g.buckets)),
	}
	g.models[key] = mm
	g.mu.Unlock()
	return mm
}

// Collect returns current GenAI metrics following OTEL GenAI semconv.
func (g *GenAIMetrics) Collect(now time.Time) []*Metric {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var metrics []*Metric

	for key, mm := range g.models {
		count := mm.requestCount.Load()
		if count == 0 {
			continue
		}

		baseLabels := map[string]string{
			"gen_ai.system": key.Provider,
			"gen_ai.response.model":  key.Model,
		}
		if key.Service != "" {
			baseLabels["service"] = key.Service
		}

		// gen_ai.client.token.usage — input tokens
		inputTokens := mm.inputTokens.Load()
		if inputTokens > 0 {
			inputLabels := copyLabels(baseLabels)
			inputLabels["gen_ai.token.type"] = "input"
			metrics = append(metrics, &Metric{
				Name:        "gen_ai.client.token.usage",
				Description: "Measures number of input and output tokens used",
				Unit:        "{token}",
				Type:        Counter,
				Value:       float64(inputTokens),
				Timestamp:   now,
				Labels:      inputLabels,
			})
		}

		// gen_ai.client.token.usage — output tokens
		outputTokens := mm.outputTokens.Load()
		if outputTokens > 0 {
			outputLabels := copyLabels(baseLabels)
			outputLabels["gen_ai.token.type"] = "output"
			metrics = append(metrics, &Metric{
				Name:        "gen_ai.client.token.usage",
				Description: "Measures number of input and output tokens used",
				Unit:        "{token}",
				Type:        Counter,
				Value:       float64(outputTokens),
				Timestamp:   now,
				Labels:      outputLabels,
			})
		}

		// gen_ai.client.operation.duration — histogram
		sumNs := mm.durationSumNs.Load()
		buckets := make([]HistogramBucket, len(g.buckets))
		var cumulative uint64
		for i, bound := range g.buckets {
			cumulative += mm.durationBuckets[i].Load()
			buckets[i] = HistogramBucket{
				UpperBound: bound,
				Count:      cumulative,
			}
		}

		durationLabels := copyLabels(baseLabels)
		if op := key.Model; op != "" {
			// operation.name would come from span but we don't track it in the key
			// to keep cardinality low — model is the primary dimension
		}

		metrics = append(metrics, &Metric{
			Name:        "gen_ai.client.operation.duration",
			Description: "GenAI operation duration",
			Unit:        "s",
			Type:        Histogram,
			Value:       float64(sumNs) / float64(time.Second),
			Timestamp:   now,
			Labels:      durationLabels,
			Histogram: &HistogramData{
				Count:   count,
				Sum:     float64(sumNs) / float64(time.Second),
				Buckets: buckets,
			},
		})
	}

	return metrics
}

func copyLabels(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
