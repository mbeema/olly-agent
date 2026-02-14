// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package correlation

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

// testLog implements CorrelableLog for testing.
type testLog struct {
	pid         int
	tid         int
	timestamp   time.Time
	traceID     string
	spanID      string
	serviceName string
}

func (l *testLog) GetPID() int              { return l.pid }
func (l *testLog) GetTID() int              { return l.tid }
func (l *testLog) GetTimestamp() time.Time   { return l.timestamp }
func (l *testLog) HasTraceContext() bool     { return l.traceID != "" }
func (l *testLog) SetTraceContext(traceID, spanID, serviceName string) {
	l.traceID = traceID
	l.spanID = spanID
	l.serviceName = serviceName
}

func TestForwardMatch(t *testing.T) {
	e := NewEngine(100*time.Millisecond, zap.NewNop())

	// Register span first, then enrich log → immediate correlation.
	e.RegisterSpanStart(1000, 2000, "trace-abc", "span-123", "", "my-service", "GET /api", time.Now())

	log := &testLog{pid: 1000, tid: 2000, timestamp: time.Now()}
	ok := e.EnrichLog(log)
	if !ok {
		t.Fatal("expected EnrichLog to return true for forward match")
	}
	if log.traceID != "trace-abc" {
		t.Errorf("expected traceID 'trace-abc', got %q", log.traceID)
	}
	if log.spanID != "span-123" {
		t.Errorf("expected spanID 'span-123', got %q", log.spanID)
	}
	if log.serviceName != "my-service" {
		t.Errorf("expected serviceName 'my-service', got %q", log.serviceName)
	}
}

func TestPIDOnlyFallback(t *testing.T) {
	e := NewEngine(100*time.Millisecond, zap.NewNop())

	// Register span on TID 2000, but log comes from TID 3000 (same PID).
	e.RegisterSpanStart(1000, 2000, "trace-xyz", "span-456", "", "svc", "op", time.Now())

	log := &testLog{pid: 1000, tid: 3000, timestamp: time.Now()}
	ok := e.EnrichLog(log)
	if !ok {
		t.Fatal("expected EnrichLog to return true for PID-only fallback")
	}
	if log.traceID != "trace-xyz" {
		t.Errorf("expected traceID 'trace-xyz', got %q", log.traceID)
	}
}

func TestTimeWindowExpired(t *testing.T) {
	e := NewEngine(50*time.Millisecond, zap.NewNop())

	// Register span with a start time 200ms in the past.
	past := time.Now().Add(-200 * time.Millisecond)
	e.RegisterSpanStart(1000, 2000, "trace-old", "span-old", "", "svc", "op", past)
	// End the span immediately so EndTime is also in the past.
	e.RegisterSpanEnd(1000, 2000)

	// Log arrives now — outside the ±50ms window of the ended span.
	log := &testLog{pid: 1000, tid: 2000, timestamp: time.Now()}
	ok := e.EnrichLog(log)
	if ok {
		t.Fatal("expected EnrichLog to return false for expired time window")
	}
	if log.traceID != "" {
		t.Errorf("expected empty traceID, got %q", log.traceID)
	}
}

func TestRetroactiveMatch(t *testing.T) {
	e := NewEngine(100*time.Millisecond, zap.NewNop())

	// Log arrives BEFORE span is registered → buffered as pending.
	log := &testLog{pid: 1000, tid: 2000, timestamp: time.Now()}
	ok := e.EnrichLog(log)
	if ok {
		t.Fatal("expected EnrichLog to return false (no active span yet)")
	}

	// Span registered → correlateWithPendingLogs fires retroactively.
	e.RegisterSpanStart(1000, 2000, "trace-retro", "span-retro", "", "svc", "op", time.Now())

	if log.traceID != "trace-retro" {
		t.Errorf("expected retroactive traceID 'trace-retro', got %q", log.traceID)
	}
}

func TestCleanStale(t *testing.T) {
	e := NewEngine(100*time.Millisecond, zap.NewNop())

	// Register span with a start time 10 minutes in the past.
	old := time.Now().Add(-10 * time.Minute)
	e.RegisterSpanStart(1000, 2000, "trace-stale", "span-stale", "", "svc", "op", old)

	if e.ActiveSpanCount() != 1 {
		t.Fatalf("expected 1 active span, got %d", e.ActiveSpanCount())
	}

	removed := e.CleanStale(5 * time.Minute)
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if e.ActiveSpanCount() != 0 {
		t.Errorf("expected 0 active spans after cleanup, got %d", e.ActiveSpanCount())
	}
}

func TestAlreadyHasTraceContext(t *testing.T) {
	e := NewEngine(100*time.Millisecond, zap.NewNop())

	// Log already has trace context → EnrichLog returns true without lookup.
	log := &testLog{pid: 1000, tid: 2000, timestamp: time.Now(), traceID: "existing"}
	ok := e.EnrichLog(log)
	if !ok {
		t.Fatal("expected EnrichLog to return true for log with existing context")
	}
	if log.traceID != "existing" {
		t.Errorf("traceID should remain 'existing', got %q", log.traceID)
	}
}

func TestStartTimeParameter(t *testing.T) {
	e := NewEngine(100*time.Millisecond, zap.NewNop())

	// Verify that the startTime parameter is actually used.
	customTime := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	e.RegisterSpanStart(1000, 2000, "trace-t", "span-t", "", "svc", "op", customTime)

	ctx := e.GetActiveSpan(1000, 2000)
	if ctx == nil {
		t.Fatal("expected active span")
	}
	if !ctx.StartTime.Equal(customTime) {
		t.Errorf("expected StartTime %v, got %v", customTime, ctx.StartTime)
	}
}

func TestZeroStartTimeFallback(t *testing.T) {
	e := NewEngine(100*time.Millisecond, zap.NewNop())

	// Zero startTime should fall back to time.Now().
	before := time.Now()
	e.RegisterSpanStart(1000, 2000, "trace-z", "span-z", "", "svc", "op", time.Time{})
	after := time.Now()

	ctx := e.GetActiveSpan(1000, 2000)
	if ctx == nil {
		t.Fatal("expected active span")
	}
	if ctx.StartTime.Before(before) || ctx.StartTime.After(after) {
		t.Errorf("expected StartTime between %v and %v, got %v", before, after, ctx.StartTime)
	}
}
