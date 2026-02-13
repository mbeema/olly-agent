// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package metrics

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/mbeema/olly/pkg/traces"
)

// DefaultMCPBuckets are the default duration histogram buckets for MCP tool calls.
// MCP calls are typically faster than GenAI (tool execution, resource reads),
// so buckets range from 5ms to 10s.
var DefaultMCPBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// MCPMetrics tracks tool call counts, duration, and error rates per tool/method.
type MCPMetrics struct {
	mu      sync.RWMutex
	tools   map[mcpToolKey]*mcpToolMetrics
	buckets []float64
}

// mcpToolKey identifies a unique MCP tool/method for metric aggregation.
type mcpToolKey struct {
	Service string
	Method  string // JSON-RPC method (e.g., "tools/call", "resources/read")
	Name    string // Tool name, resource URI, or prompt name
}

type mcpToolMetrics struct {
	requestCount    atomic.Uint64
	errorCount      atomic.Uint64
	durationSumNs   atomic.Int64
	durationBuckets []atomic.Uint64
	overflowCount   atomic.Uint64
}

// NewMCPMetrics creates a new MCP metrics tracker.
func NewMCPMetrics(buckets []float64) *MCPMetrics {
	if len(buckets) == 0 {
		buckets = DefaultMCPBuckets
	}
	return &MCPMetrics{
		tools:   make(map[mcpToolKey]*mcpToolMetrics),
		buckets: buckets,
	}
}

// RecordSpan records metrics from a completed MCP span.
func (m *MCPMetrics) RecordSpan(span *traces.Span) {
	if span.Protocol != "mcp" {
		return
	}

	method := span.Attributes["mcp.method.name"]
	if method == "" {
		return
	}

	// Determine the name dimension based on method
	name := ""
	switch {
	case method == "tools/call":
		name = span.Attributes["gen_ai.tool.name"]
	case method == "resources/read":
		name = span.Attributes["mcp.resource.uri"]
	case method == "prompts/get":
		name = span.Attributes["gen_ai.prompt.name"]
	}

	key := mcpToolKey{
		Service: span.ServiceName,
		Method:  method,
		Name:    name,
	}

	mm := m.getOrCreate(key)
	mm.requestCount.Add(1)

	// Track errors
	if span.Status == traces.StatusError {
		mm.errorCount.Add(1)
	}

	// Record duration
	durationSec := span.Duration.Seconds()
	mm.durationSumNs.Add(span.Duration.Nanoseconds())

	placed := false
	for i, bound := range m.buckets {
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

func (m *MCPMetrics) getOrCreate(key mcpToolKey) *mcpToolMetrics {
	m.mu.RLock()
	mm, ok := m.tools[key]
	m.mu.RUnlock()
	if ok {
		return mm
	}

	m.mu.Lock()
	if mm, ok = m.tools[key]; ok {
		m.mu.Unlock()
		return mm
	}
	mm = &mcpToolMetrics{
		durationBuckets: make([]atomic.Uint64, len(m.buckets)),
	}
	m.tools[key] = mm
	m.mu.Unlock()
	return mm
}

// Collect returns current MCP metrics.
func (m *MCPMetrics) Collect(now time.Time) []*Metric {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var metrics []*Metric

	for key, mm := range m.tools {
		count := mm.requestCount.Load()
		if count == 0 {
			continue
		}

		baseLabels := map[string]string{
			"mcp.method.name": key.Method,
		}
		if key.Name != "" {
			baseLabels["mcp.name"] = key.Name
		}
		if key.Service != "" {
			baseLabels["service"] = key.Service
		}

		// mcp.client.request.count
		metrics = append(metrics, &Metric{
			Name:        "mcp.client.request.count",
			Description: "Number of MCP requests",
			Unit:        "{request}",
			Type:        Counter,
			Value:       float64(count),
			Timestamp:   now,
			Labels:      copyLabels(baseLabels),
		})

		// mcp.client.error.count
		errCount := mm.errorCount.Load()
		if errCount > 0 {
			metrics = append(metrics, &Metric{
				Name:        "mcp.client.error.count",
				Description: "Number of MCP errors",
				Unit:        "{error}",
				Type:        Counter,
				Value:       float64(errCount),
				Timestamp:   now,
				Labels:      copyLabels(baseLabels),
			})
		}

		// mcp.client.duration — histogram
		sumNs := mm.durationSumNs.Load()
		buckets := make([]HistogramBucket, len(m.buckets))
		var cumulative uint64
		for i, bound := range m.buckets {
			cumulative += mm.durationBuckets[i].Load()
			buckets[i] = HistogramBucket{
				UpperBound: bound,
				Count:      cumulative,
			}
		}

		metrics = append(metrics, &Metric{
			Name:        "mcp.client.operation.duration",
			Description: "MCP request duration",
			Unit:        "s",
			Type:        Histogram,
			Value:       float64(sumNs) / float64(time.Second),
			Timestamp:   now,
			Labels:      copyLabels(baseLabels),
			Histogram: &HistogramData{
				Count:   count,
				Sum:     float64(sumNs) / float64(time.Second),
				Buckets: buckets,
			},
		})
	}

	return metrics
}
