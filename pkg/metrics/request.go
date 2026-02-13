// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package metrics

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mbeema/olly/pkg/traces"
)

// RequestMetrics tracks RED (Rate, Errors, Duration) metrics per service.
type RequestMetrics struct {
	mu        sync.RWMutex
	services  map[string]*serviceMetrics
	buckets   []float64
	startTime time.Time // OTLP StartTimeUnixNano for cumulative metrics
}

type serviceMetrics struct {
	requestCount   atomic.Uint64
	errorCount     atomic.Uint64
	latencySum     atomic.Int64 // nanoseconds
	latencyBuckets []atomic.Uint64
}

// DefaultBuckets are the default histogram bucket boundaries in seconds.
var DefaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// NewRequestMetrics creates a new RED metrics tracker.
func NewRequestMetrics(buckets []float64) *RequestMetrics {
	if len(buckets) == 0 {
		buckets = DefaultBuckets
	}
	return &RequestMetrics{
		services:  make(map[string]*serviceMetrics),
		buckets:   buckets,
		startTime: time.Now(),
	}
}

// RecordSpan records metrics from a completed span.
func (r *RequestMetrics) RecordSpan(span *traces.Span) {
	service := span.ServiceName
	if service == "" {
		service = "unknown"
	}

	sm := r.getOrCreate(service)

	sm.requestCount.Add(1)

	if span.Status == traces.StatusError {
		sm.errorCount.Add(1)
	}

	durationSec := span.Duration.Seconds()
	sm.latencySum.Add(span.Duration.Nanoseconds())

	// Update histogram buckets (non-cumulative; cumulative computed at export)
	for i, bound := range r.buckets {
		if durationSec <= bound {
			sm.latencyBuckets[i].Add(1)
			return
		}
	}
	// +Inf overflow: counted via total count minus cumulative at export
}

func (r *RequestMetrics) getOrCreate(service string) *serviceMetrics {
	r.mu.RLock()
	sm, ok := r.services[service]
	r.mu.RUnlock()

	if ok {
		return sm
	}

	r.mu.Lock()
	if sm, ok = r.services[service]; ok {
		r.mu.Unlock()
		return sm
	}

	sm = &serviceMetrics{
		latencyBuckets: make([]atomic.Uint64, len(r.buckets)),
	}
	r.services[service] = sm
	r.mu.Unlock()

	return sm
}

// Collect returns current RED metrics as a slice.
// R5.1: Uses OTEL standard metric names with proper histogram export.
func (r *RequestMetrics) Collect(now time.Time) []*Metric {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var metrics []*Metric

	for service, sm := range r.services {
		labels := map[string]string{"service": service}
		count := sm.requestCount.Load()
		sumNs := sm.latencySum.Load()

		if count > 0 {
			// R5.1: http.server.request.duration histogram (OTEL stable name)
			// Build cumulative bucket counts from non-cumulative internal counts
			buckets := make([]HistogramBucket, len(r.buckets))
			var cumulative uint64
			for i, bound := range r.buckets {
				cumulative += sm.latencyBuckets[i].Load()
				buckets[i] = HistogramBucket{
					UpperBound: bound,
					Count:      cumulative,
				}
			}

			metrics = append(metrics, &Metric{
				Name:        "http.server.request.duration",
				Description: "Duration of HTTP server requests",
				Unit:        "s",
				Type:        Histogram,
				Value:       float64(sumNs) / float64(time.Second),
				Timestamp:   now,
				StartTime:   r.startTime,
				Labels:      labels,
				Histogram: &HistogramData{
					Count:   count,
					Sum:     float64(sumNs) / float64(time.Second),
					Buckets: buckets,
				},
			})

			// Percentile estimates (convenience gauges)
			metrics = append(metrics, &Metric{
				Name:      "http.server.request.duration.p50",
				Unit:      "s",
				Type:      Gauge,
				Value:     r.percentile(sm, 0.5),
				Timestamp: now,
				Labels:    labels,
			})

			metrics = append(metrics, &Metric{
				Name:      "http.server.request.duration.p99",
				Unit:      "s",
				Type:      Gauge,
				Value:     r.percentile(sm, 0.99),
				Timestamp: now,
				Labels:    labels,
			})
		}
	}

	return metrics
}

func (r *RequestMetrics) percentile(sm *serviceMetrics, p float64) float64 {
	total := sm.requestCount.Load()
	if total == 0 {
		return 0
	}

	target := uint64(float64(total) * p)
	var cumulative uint64

	for i, bound := range r.buckets {
		cumulative += sm.latencyBuckets[i].Load()
		if cumulative >= target {
			return bound
		}
	}

	return r.buckets[len(r.buckets)-1]
}

// Summary returns a human-readable summary for a service.
func (r *RequestMetrics) Summary(service string) string {
	r.mu.RLock()
	sm, ok := r.services[service]
	r.mu.RUnlock()

	if !ok {
		return "no data"
	}

	count := sm.requestCount.Load()
	errors := sm.errorCount.Load()
	sumNs := sm.latencySum.Load()

	avgMs := float64(0)
	if count > 0 {
		avgMs = float64(sumNs) / float64(count) / float64(time.Millisecond)
	}

	errorRate := float64(0)
	if count > 0 {
		errorRate = float64(errors) / float64(count) * 100
	}

	return fmt.Sprintf("requests=%d errors=%d (%.1f%%) avg_latency=%.1fms",
		count, errors, errorRate, avgMs)
}
