// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package health

import (
	"runtime"
	"sync/atomic"
	"time"
)

// Stats tracks self-monitoring counters for the agent.
type Stats struct {
	startTime time.Time

	SpansReceived  atomic.Int64
	SpansExported  atomic.Int64
	SpansDropped   atomic.Int64
	LogsReceived   atomic.Int64
	LogsExported   atomic.Int64
	LogsDropped    atomic.Int64
	MetricsExported atomic.Int64
	MetricsDropped  atomic.Int64
	ProfilesExported atomic.Int64
	ProfilesDropped  atomic.Int64
}

// NewStats creates a new Stats instance.
func NewStats() *Stats {
	return &Stats{
		startTime: time.Now(),
	}
}

// Uptime returns agent uptime.
func (s *Stats) Uptime() time.Duration {
	return time.Since(s.startTime)
}

// Snapshot returns a point-in-time copy of all counters.
type Snapshot struct {
	UptimeSeconds    float64
	Goroutines       int
	MemoryRSSBytes   uint64
	SpansReceived    int64
	SpansExported    int64
	SpansDropped     int64
	LogsReceived     int64
	LogsExported     int64
	LogsDropped      int64
	MetricsExported  int64
	MetricsDropped   int64
	ProfilesExported int64
	ProfilesDropped  int64
}

// Snapshot returns current stats.
func (s *Stats) Snapshot() Snapshot {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return Snapshot{
		UptimeSeconds:    s.Uptime().Seconds(),
		Goroutines:       runtime.NumGoroutine(),
		MemoryRSSBytes:   memStats.Sys,
		SpansReceived:    s.SpansReceived.Load(),
		SpansExported:    s.SpansExported.Load(),
		SpansDropped:     s.SpansDropped.Load(),
		LogsReceived:     s.LogsReceived.Load(),
		LogsExported:     s.LogsExported.Load(),
		LogsDropped:      s.LogsDropped.Load(),
		MetricsExported:  s.MetricsExported.Load(),
		MetricsDropped:   s.MetricsDropped.Load(),
		ProfilesExported: s.ProfilesExported.Load(),
		ProfilesDropped:  s.ProfilesDropped.Load(),
	}
}

// PrometheusMetrics returns stats in Prometheus text exposition format.
func (s *Stats) PrometheusMetrics() string {
	snap := s.Snapshot()
	return prometheusFormat(snap)
}

func prometheusFormat(snap Snapshot) string {
	var b []byte
	b = appendMetric(b, "olly_agent_uptime_seconds", "gauge", "Agent uptime in seconds", snap.UptimeSeconds)
	b = appendMetric(b, "olly_agent_goroutines", "gauge", "Number of goroutines", float64(snap.Goroutines))
	b = appendMetric(b, "olly_agent_memory_rss_bytes", "gauge", "Memory usage in bytes", float64(snap.MemoryRSSBytes))
	b = appendMetric(b, "olly_spans_received_total", "counter", "Total spans received", float64(snap.SpansReceived))
	b = appendMetric(b, "olly_spans_exported_total", "counter", "Total spans exported", float64(snap.SpansExported))
	b = appendMetric(b, "olly_spans_dropped_total", "counter", "Total spans dropped", float64(snap.SpansDropped))
	b = appendMetric(b, "olly_logs_received_total", "counter", "Total logs received", float64(snap.LogsReceived))
	b = appendMetric(b, "olly_logs_exported_total", "counter", "Total logs exported", float64(snap.LogsExported))
	b = appendMetric(b, "olly_logs_dropped_total", "counter", "Total logs dropped", float64(snap.LogsDropped))
	b = appendMetric(b, "olly_metrics_exported_total", "counter", "Total metrics exported", float64(snap.MetricsExported))
	b = appendMetric(b, "olly_metrics_dropped_total", "counter", "Total metrics dropped", float64(snap.MetricsDropped))
	b = appendMetric(b, "olly_profiles_exported_total", "counter", "Total profiles exported", float64(snap.ProfilesExported))
	b = appendMetric(b, "olly_profiles_dropped_total", "counter", "Total profiles dropped", float64(snap.ProfilesDropped))
	return string(b)
}

func appendMetric(b []byte, name, typ, help string, value float64) []byte {
	b = append(b, "# HELP "...)
	b = append(b, name...)
	b = append(b, ' ')
	b = append(b, help...)
	b = append(b, '\n')
	b = append(b, "# TYPE "...)
	b = append(b, name...)
	b = append(b, ' ')
	b = append(b, typ...)
	b = append(b, '\n')
	b = append(b, name...)
	b = append(b, ' ')
	b = appendFloat(b, value)
	b = append(b, '\n')
	return b
}

func appendFloat(b []byte, f float64) []byte {
	// Use simple formatting; avoid importing strconv for this
	if f == float64(int64(f)) {
		return append(b, []byte(intToStr(int64(f)))...)
	}
	// Use fmt-free float formatting for common cases
	return append(b, []byte(floatToStr(f))...)
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte(n%10) + '0'
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func floatToStr(f float64) string {
	// Simple 6 decimal place formatting
	neg := f < 0
	if neg {
		f = -f
	}
	whole := int64(f)
	frac := int64((f - float64(whole)) * 1000000)
	if frac < 0 {
		frac = -frac
	}

	s := intToStr(whole) + "."
	fracStr := intToStr(frac)
	// Pad to 6 digits
	for len(fracStr) < 6 {
		fracStr = "0" + fracStr
	}
	s += fracStr

	// Trim trailing zeros after decimal
	for len(s) > 1 && s[len(s)-1] == '0' {
		s = s[:len(s)-1]
	}
	if s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}

	if neg {
		s = "-" + s
	}
	return s
}
