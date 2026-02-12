// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package correlation

import (
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
)

// CorrelableLog is the interface that log records must implement for correlation.
type CorrelableLog interface {
	GetPID() int
	GetTID() int
	GetTimestamp() time.Time
	SetTraceContext(traceID, spanID, serviceName string)
	HasTraceContext() bool
}

// SpanContext holds the trace context of an active span.
type SpanContext struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	PID          uint32
	TID          uint32
	StartTime    time.Time
	EndTime      time.Time
	ServiceName  string
	Operation    string
}

// Engine correlates logs with traces using PID+TID+timestamp matching.
type Engine struct {
	logger *zap.Logger
	window time.Duration

	mu          sync.RWMutex
	activeSpans map[uint64]*SpanContext // key: PID<<32 | TID
	pendingLogs []*pendingLog

	spanCallbacks []func(*SpanContext)
}

type pendingLog struct {
	log       CorrelableLog
	timestamp time.Time
}

// NewEngine creates a new correlation engine.
func NewEngine(window time.Duration, logger *zap.Logger) *Engine {
	if window == 0 {
		window = 100 * time.Millisecond
	}

	return &Engine{
		logger:      logger,
		window:      window,
		activeSpans: make(map[uint64]*SpanContext),
	}
}

// OnSpanComplete registers a callback for completed spans.
func (e *Engine) OnSpanComplete(fn func(*SpanContext)) {
	e.mu.Lock()
	e.spanCallbacks = append(e.spanCallbacks, fn)
	e.mu.Unlock()
}

// RegisterSpanStart records the start of a span for correlation.
func (e *Engine) RegisterSpanStart(pid, tid uint32, traceID, spanID, parentSpanID, serviceName, operation string) {
	key := makeKey(pid, tid)

	ctx := &SpanContext{
		TraceID:      traceID,
		SpanID:       spanID,
		ParentSpanID: parentSpanID,
		PID:          pid,
		TID:          tid,
		StartTime:    time.Now(),
		ServiceName:  serviceName,
		Operation:    operation,
	}

	e.mu.Lock()
	e.activeSpans[key] = ctx
	e.mu.Unlock()

	// Try to correlate with pending logs
	e.correlateWithPendingLogs(ctx)
}

// RegisterSpanEnd marks a span as complete.
func (e *Engine) RegisterSpanEnd(pid, tid uint32) {
	key := makeKey(pid, tid)

	e.mu.Lock()
	ctx, ok := e.activeSpans[key]
	if ok {
		ctx.EndTime = time.Now()
		delete(e.activeSpans, key)
	}
	cbs := e.spanCallbacks
	e.mu.Unlock()

	if ok {
		for _, cb := range cbs {
			cb(ctx)
		}
	}
}

// EnrichLog attempts to add trace context to a log record.
func (e *Engine) EnrichLog(log CorrelableLog) bool {
	if log.HasTraceContext() {
		return true
	}

	pid := log.GetPID()
	tid := log.GetTID()
	ts := log.GetTimestamp()

	// Try exact PID+TID match first
	if pid > 0 && tid > 0 {
		key := makeKey(uint32(pid), uint32(tid))

		e.mu.RLock()
		ctx, ok := e.activeSpans[key]
		e.mu.RUnlock()

		if ok && e.isWithinWindow(ts, ctx) {
			log.SetTraceContext(ctx.TraceID, ctx.SpanID, ctx.ServiceName)
			return true
		}
	}

	// Try PID-only match (TID=0 means any thread)
	if pid > 0 {
		e.mu.RLock()
		for _, ctx := range e.activeSpans {
			if ctx.PID == uint32(pid) && e.isWithinWindow(ts, ctx) {
				e.mu.RUnlock()
				log.SetTraceContext(ctx.TraceID, ctx.SpanID, ctx.ServiceName)
				return true
			}
		}
		e.mu.RUnlock()
	}

	// Buffer the log for retroactive correlation
	e.bufferPendingLog(log)
	return false
}

func (e *Engine) isWithinWindow(ts time.Time, ctx *SpanContext) bool {
	spanStart := ctx.StartTime.Add(-e.window)
	spanEnd := ctx.EndTime
	if spanEnd.IsZero() {
		spanEnd = time.Now()
	}
	spanEnd = spanEnd.Add(e.window)

	return !ts.Before(spanStart) && !ts.After(spanEnd)
}

func (e *Engine) bufferPendingLog(log CorrelableLog) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.pendingLogs = append(e.pendingLogs, &pendingLog{
		log:       log,
		timestamp: time.Now(),
	})

	// Trim old pending logs (keep last 1000, remove expired)
	const maxPending = 1000
	if len(e.pendingLogs) > maxPending {
		e.pendingLogs = e.pendingLogs[len(e.pendingLogs)-maxPending:]
	}

	cutoff := time.Now().Add(-2 * e.window)
	start := 0
	for start < len(e.pendingLogs) && e.pendingLogs[start].timestamp.Before(cutoff) {
		start++
	}
	if start > 0 {
		e.pendingLogs = e.pendingLogs[start:]
	}
}

func (e *Engine) correlateWithPendingLogs(ctx *SpanContext) {
	e.mu.Lock()
	defer e.mu.Unlock()

	remaining := e.pendingLogs[:0]
	for _, pl := range e.pendingLogs {
		log := pl.log
		pid := log.GetPID()
		ts := log.GetTimestamp()

		if uint32(pid) == ctx.PID && e.isWithinWindow(ts, ctx) {
			log.SetTraceContext(ctx.TraceID, ctx.SpanID, ctx.ServiceName)
		} else {
			remaining = append(remaining, pl)
		}
	}
	e.pendingLogs = remaining
}

// GetActiveSpan returns the active span for a PID+TID, if any.
func (e *Engine) GetActiveSpan(pid, tid uint32) *SpanContext {
	key := makeKey(pid, tid)

	e.mu.RLock()
	ctx := e.activeSpans[key]
	e.mu.RUnlock()

	return ctx
}

// CleanStale removes spans older than maxAge.
func (e *Engine) CleanStale(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	e.mu.Lock()
	for key, ctx := range e.activeSpans {
		if ctx.StartTime.Before(cutoff) {
			delete(e.activeSpans, key)
			removed++
		}
	}
	e.mu.Unlock()

	return removed
}

// ActiveSpanCount returns the number of active spans.
func (e *Engine) ActiveSpanCount() int {
	e.mu.RLock()
	n := len(e.activeSpans)
	e.mu.RUnlock()
	return n
}

// Start begins periodic cleanup.
func (e *Engine) Start(ctx context.Context) error {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				removed := e.CleanStale(5 * time.Minute)
				if removed > 0 {
					e.logger.Debug("cleaned stale spans", zap.Int("removed", removed))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return nil
}

// Stop is a no-op; cleanup goroutine uses context cancellation.
func (e *Engine) Stop() error {
	return nil
}

func makeKey(pid, tid uint32) uint64 {
	return uint64(pid)<<32 | uint64(tid)
}
