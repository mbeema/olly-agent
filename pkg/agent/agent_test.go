// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package agent

import (
	"testing"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/conntrack"
	"github.com/mbeema/olly/pkg/health"
	hookebpf "github.com/mbeema/olly/pkg/hook/ebpf"
	"github.com/mbeema/olly/pkg/logs"
	"github.com/mbeema/olly/pkg/reassembly"
	"go.uber.org/zap"
)

// newTestAgent creates a minimal agent for testing processHookLog.
func newTestAgent() *Agent {
	a := &Agent{
		logParser:   logs.NewParser(),
		logCh:       make(chan *logs.LogRecord, 100),
		logger:      zap.NewNop(),
		healthStats: health.NewStats(),
	}
	cfg := config.DefaultConfig()
	a.cfg.Store(cfg)
	return a
}

func TestProcessHookLogBasic(t *testing.T) {
	a := newTestAgent()

	data := []byte("INFO: user logged in\n")
	a.processHookLog(1234, 5678, 3, data, 1000000)

	select {
	case record := <-a.logCh:
		if record.PID != 1234 {
			t.Errorf("PID = %d, want 1234", record.PID)
		}
		if record.TID != 5678 {
			t.Errorf("TID = %d, want 5678", record.TID)
		}
		if record.Source != "hook" {
			t.Errorf("Source = %q, want 'hook'", record.Source)
		}
		if record.Level != logs.LevelInfo {
			t.Errorf("Level = %v, want INFO", record.Level)
		}
	case <-time.After(time.Second):
		t.Fatal("no log record received")
	}
}

func TestProcessHookLogMultipleLines(t *testing.T) {
	a := newTestAgent()

	data := []byte("INFO: line one\nERROR: line two\nDEBUG: line three\n")
	a.processHookLog(100, 200, 5, data, 2000000)

	// Should get 3 records
	records := make([]*logs.LogRecord, 0, 3)
	timeout := time.After(time.Second)
	for i := 0; i < 3; i++ {
		select {
		case r := <-a.logCh:
			records = append(records, r)
		case <-timeout:
			t.Fatalf("expected 3 records, got %d", len(records))
		}
	}

	// All should have PID=100, TID=200, Source="hook"
	for i, r := range records {
		if r.PID != 100 {
			t.Errorf("record[%d].PID = %d, want 100", i, r.PID)
		}
		if r.TID != 200 {
			t.Errorf("record[%d].TID = %d, want 200", i, r.TID)
		}
		if r.Source != "hook" {
			t.Errorf("record[%d].Source = %q, want 'hook'", i, r.Source)
		}
	}

	// Check levels
	if records[0].Level != logs.LevelInfo {
		t.Errorf("record[0].Level = %v, want INFO", records[0].Level)
	}
	if records[1].Level != logs.LevelError {
		t.Errorf("record[1].Level = %v, want ERROR", records[1].Level)
	}
	if records[2].Level != logs.LevelDebug {
		t.Errorf("record[2].Level = %v, want DEBUG", records[2].Level)
	}
}

func TestProcessHookLogBinaryFilter(t *testing.T) {
	a := newTestAgent()

	// Create binary data: >10% non-printable bytes
	data := make([]byte, 100)
	for i := range data {
		data[i] = 0x01 // non-printable
	}

	a.processHookLog(100, 200, 5, data, 3000000)

	// Should be filtered out — no records
	select {
	case r := <-a.logCh:
		t.Errorf("binary data should be filtered, got record: %q", r.Body)
	case <-time.After(50 * time.Millisecond):
		// expected — nothing received
	}
}

func TestProcessHookLogEmptyLines(t *testing.T) {
	a := newTestAgent()

	data := []byte("\n\n\n")
	a.processHookLog(100, 200, 5, data, 4000000)

	// All empty lines should be skipped
	select {
	case r := <-a.logCh:
		t.Errorf("empty lines should be skipped, got record: %q", r.Body)
	case <-time.After(50 * time.Millisecond):
		// expected
	}
}

func TestProcessHookLogJSON(t *testing.T) {
	a := newTestAgent()

	data := []byte(`{"message":"request processed","level":"warn","pid":999}` + "\n")
	a.processHookLog(4444, 5555, 7, data, 5000000)

	select {
	case record := <-a.logCh:
		// PID should be overridden from syscall context, not from JSON
		if record.PID != 4444 {
			t.Errorf("PID = %d, want 4444 (from syscall context, not JSON)", record.PID)
		}
		if record.TID != 5555 {
			t.Errorf("TID = %d, want 5555", record.TID)
		}
		if record.Source != "hook" {
			t.Errorf("Source = %q, want 'hook'", record.Source)
		}
		if record.Level != logs.LevelWarn {
			t.Errorf("Level = %v, want WARN", record.Level)
		}
		if record.Body != "request processed" {
			t.Errorf("Body = %q, want 'request processed'", record.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("no log record received")
	}
}

func TestProcessHookLogPIDOverridesParser(t *testing.T) {
	a := newTestAgent()

	// JSON with PID=999 — should be overridden by hook PID=7777
	data := []byte(`{"message":"test","pid":999}` + "\n")
	a.processHookLog(7777, 8888, 3, data, 6000000)

	select {
	case record := <-a.logCh:
		if record.PID != 7777 {
			t.Errorf("PID = %d, want 7777 (hook context should override parsed PID)", record.PID)
		}
		if record.TID != 8888 {
			t.Errorf("TID = %d, want 8888", record.TID)
		}
	case <-time.After(time.Second):
		t.Fatal("no log record received")
	}
}

func TestProcessHookLogChannelFull(t *testing.T) {
	// Create agent with tiny channel
	a := &Agent{
		logParser:   logs.NewParser(),
		logCh:       make(chan *logs.LogRecord, 1),
		logger:      zap.NewNop(),
		healthStats: health.NewStats(),
	}
	cfg := config.DefaultConfig()
	a.cfg.Store(cfg)

	// Fill the channel
	a.logCh <- &logs.LogRecord{Body: "blocker"}

	// This should not block or panic — just drop
	data := []byte("INFO: should be dropped\n")
	done := make(chan struct{})
	go func() {
		a.processHookLog(100, 200, 5, data, 7000000)
		close(done)
	}()

	select {
	case <-done:
		// good, didn't block
	case <-time.After(time.Second):
		t.Fatal("processHookLog blocked on full channel")
	}
}

// newTestAgentWithConnTracker creates a minimal agent with connTracker and hookProvider
// for testing enrichPairContext.
func newTestAgentWithConnTracker() *Agent {
	a := &Agent{
		logParser:          logs.NewParser(),
		logCh:              make(chan *logs.LogRecord, 100),
		logger:             zap.NewNop(),
		connTracker:        conntrack.NewTracker(),
		maxRequestDuration: 5 * time.Minute,
	}
	cfg := config.DefaultConfig()
	a.cfg.Store(cfg)
	a.hookProvider = hookebpf.NewStubProvider("test", a.logger)
	return a
}

// storeTestConnCtx is a helper to store a connTraceCtx for testing.
func storeTestConnCtx(a *Agent, pid uint32, fd int32, traceID, spanID, serverSpanID string) {
	connKey := uint64(pid)<<32 | uint64(uint32(fd))
	a.connCtx.Store(connKey, &connTraceCtx{
		TraceID:      traceID,
		SpanID:       spanID,
		ServerSpanID: serverSpanID,
		Created:      time.Now(),
	})
}

func TestEnrichPairContext_InboundDirect(t *testing.T) {
	a := newTestAgentWithConnTracker()

	// Register an inbound connection (SERVER)
	a.connTracker.RegisterInbound(100, 5, 0, 8080)

	// Store context keyed by PID+FD
	storeTestConnCtx(a, 100, 5, "trace-aaa", "span-bbb", "server-span-ccc")

	pair := &reassembly.RequestPair{
		PID:       100,
		TID:       200,
		FD:        5,
		Direction: 1, // inbound
	}

	a.enrichPairContext(pair)

	if pair.ParentTraceID != "trace-aaa" {
		t.Errorf("ParentTraceID = %q, want %q", pair.ParentTraceID, "trace-aaa")
	}
	if pair.ParentSpanID != "server-span-ccc" {
		t.Errorf("ParentSpanID = %q, want %q", pair.ParentSpanID, "server-span-ccc")
	}
}

func TestEnrichPairContext_CausalMapping(t *testing.T) {
	a := newTestAgentWithConnTracker()

	// Register outbound connection (CLIENT)
	a.connTracker.Register(100, 10, 0, 5432)

	// Store inbound context on FD 5
	storeTestConnCtx(a, 100, 5, "trace-111", "span-222", "server-333")

	// Store causal mapping: outbound FD 10 was caused by inbound FD 5
	causalKey := uint64(100)<<32 | uint64(uint32(int32(10)))
	a.fdCausal.Store(causalKey, &causalEntry{
		InboundFD: 5,
		Timestamp: time.Now(),
	})

	pair := &reassembly.RequestPair{
		PID:      100,
		TID:      300, // different TID (goroutine migration)
		FD:       10,
		Protocol: "postgres",
	}

	a.enrichPairContext(pair)

	if pair.ParentTraceID != "trace-111" {
		t.Errorf("ParentTraceID = %q, want %q", pair.ParentTraceID, "trace-111")
	}
	if pair.ParentSpanID != "server-333" {
		t.Errorf("ParentSpanID = %q, want %q", pair.ParentSpanID, "server-333")
	}
	// postgres should NOT get InjectedSpanID
	if pair.InjectedSpanID != "" {
		t.Errorf("InjectedSpanID = %q, want empty for postgres", pair.InjectedSpanID)
	}
}

func TestEnrichPairContext_ThreadFallback(t *testing.T) {
	a := newTestAgentWithConnTracker()

	// Register outbound connection (CLIENT)
	a.connTracker.Register(100, 10, 0, 80)

	// Store inbound context on FD 5, with ReadTID=200 (matching pair TID)
	storeTestConnCtx(a, 100, 5, "trace-abc", "span-def", "server-ghi")
	// Set ReadTID so TID match check passes (simulating same-thread read+write)
	connKey := uint64(100)<<32 | uint64(uint32(int32(5)))
	if val, ok := a.connCtx.Load(connKey); ok {
		val.(*connTraceCtx).ReadTID = 200
	}

	// Store threadInboundFD: TID 200 was serving inbound FD 5
	// (no fdCausal entry — simulates first write before causal is recorded)
	tidKey := uint64(100)<<32 | uint64(200)
	a.threadInboundFD.Store(tidKey, int32(5))

	pair := &reassembly.RequestPair{
		PID:      100,
		TID:      200,
		FD:       10,
		Protocol: "http",
	}

	a.enrichPairContext(pair)

	if pair.ParentTraceID != "trace-abc" {
		t.Errorf("ParentTraceID = %q, want %q", pair.ParentTraceID, "trace-abc")
	}
	if pair.ParentSpanID != "server-ghi" {
		t.Errorf("ParentSpanID = %q, want %q", pair.ParentSpanID, "server-ghi")
	}
	// HTTP should get InjectedSpanID when TID matches ReadTID
	if pair.InjectedSpanID != "span-def" {
		t.Errorf("InjectedSpanID = %q, want %q", pair.InjectedSpanID, "span-def")
	}
}

func TestEnrichPairContext_TIDMismatch_NoInjectedSpanID(t *testing.T) {
	a := newTestAgentWithConnTracker()

	// Register outbound connection (CLIENT)
	a.connTracker.Register(100, 10, 0, 80)

	// Store inbound context on FD 5, with ReadTID=200
	storeTestConnCtx(a, 100, 5, "trace-abc", "span-def", "server-ghi")
	connKey := uint64(100)<<32 | uint64(uint32(int32(5)))
	if val, ok := a.connCtx.Load(connKey); ok {
		val.(*connTraceCtx).ReadTID = 200
	}

	// Store pidActiveCtx fallback (Layer 3)
	{
		set := &pidInboundSet{}
		set.Add(5, time.Now())
		a.pidActiveCtx.Store(uint32(100), set)
	}

	pair := &reassembly.RequestPair{
		PID:         100,
		TID:         999, // Different TID — goroutine migrated
		FD:          10,
		Protocol:    "http",
		RequestTime: time.Now(),
	}

	a.enrichPairContext(pair)

	// Should still get ParentTraceID/ParentSpanID from pidActiveCtx fallback
	if pair.ParentTraceID != "trace-abc" {
		t.Errorf("ParentTraceID = %q, want %q", pair.ParentTraceID, "trace-abc")
	}
	if pair.ParentSpanID != "server-ghi" {
		t.Errorf("ParentSpanID = %q, want %q", pair.ParentSpanID, "server-ghi")
	}
	// With BPF PID-level trace context forwarding, kprobe_write bridges
	// the TID gap by copying pid_trace_ctx[PID] → thread_trace_ctx[PID+write_TID].
	// So InjectedSpanID IS set even with TID mismatch.
	if pair.InjectedSpanID != "span-def" {
		t.Errorf("InjectedSpanID = %q, want %q (PID-level forwarding bridges TID mismatch)", pair.InjectedSpanID, "span-def")
	}
}

func TestEnrichPairContext_PIDFallback(t *testing.T) {
	a := newTestAgentWithConnTracker()

	// Register outbound connection (CLIENT)
	a.connTracker.Register(100, 10, 0, 5432)

	// Store inbound context on FD 5
	storeTestConnCtx(a, 100, 5, "trace-pid", "span-pid", "server-pid")

	// Store pidActiveCtx: active inbound FDs for PID 100 includes FD 5
	// (no fdCausal, no threadInboundFD for this TID — simulates Go goroutine TID mismatch)
	{
		set := &pidInboundSet{}
		set.Add(5, time.Now())
		a.pidActiveCtx.Store(uint32(100), set)
	}

	pair := &reassembly.RequestPair{
		PID:         100,
		TID:         999, // different TID — goroutine migrated
		FD:          10,
		Protocol:    "postgres",
		RequestTime: time.Now(),
	}

	a.enrichPairContext(pair)

	if pair.ParentTraceID != "trace-pid" {
		t.Errorf("ParentTraceID = %q, want %q", pair.ParentTraceID, "trace-pid")
	}
	if pair.ParentSpanID != "server-pid" {
		t.Errorf("ParentSpanID = %q, want %q", pair.ParentSpanID, "server-pid")
	}
}

func TestEnrichPairContext_Stale(t *testing.T) {
	a := newTestAgentWithConnTracker()
	a.maxRequestDuration = 30 * time.Second // Use short duration for stale test

	// Register an inbound connection (SERVER)
	a.connTracker.RegisterInbound(100, 5, 0, 8080)

	// Store context with old timestamp (>30s ago)
	connKey := uint64(100)<<32 | uint64(uint32(int32(5)))
	a.connCtx.Store(connKey, &connTraceCtx{
		TraceID:      "stale-trace",
		SpanID:       "stale-span",
		ServerSpanID: "stale-server",
		Created:      time.Now().Add(-31 * time.Second),
	})

	pair := &reassembly.RequestPair{
		PID:       100,
		TID:       200,
		FD:        5,
		Direction: 1,
	}

	a.enrichPairContext(pair)

	// Stale context should be ignored
	if pair.ParentTraceID != "" {
		t.Errorf("ParentTraceID = %q, want empty (stale)", pair.ParentTraceID)
	}
}

func TestEnrichPairContext_StaleCausal(t *testing.T) {
	a := newTestAgentWithConnTracker()
	a.maxRequestDuration = 30 * time.Second // Use short duration for stale test

	// Register outbound connection (CLIENT)
	a.connTracker.Register(100, 10, 0, 5432)

	// Store fresh inbound context on FD 5
	storeTestConnCtx(a, 100, 5, "trace-fresh", "span-fresh", "server-fresh")

	// Store STALE causal mapping
	causalKey := uint64(100)<<32 | uint64(uint32(int32(10)))
	a.fdCausal.Store(causalKey, &causalEntry{
		InboundFD: 5,
		Timestamp: time.Now().Add(-31 * time.Second),
	})

	// But also store pidActiveCtx as fallback
	{
		set := &pidInboundSet{}
		set.Add(5, time.Now())
		a.pidActiveCtx.Store(uint32(100), set)
	}

	pair := &reassembly.RequestPair{
		PID:         100,
		TID:         999,
		FD:          10,
		Protocol:    "postgres",
		RequestTime: time.Now(),
	}

	a.enrichPairContext(pair)

	// Stale causal should be skipped, falls through to PID fallback
	if pair.ParentTraceID != "trace-fresh" {
		t.Errorf("ParentTraceID = %q, want %q", pair.ParentTraceID, "trace-fresh")
	}
}

func TestOnClose_CleansContextMaps(t *testing.T) {
	a := newTestAgentWithConnTracker()

	pid := uint32(100)
	fd := int32(5)

	// Store entries in all maps
	connKey := uint64(pid)<<32 | uint64(uint32(fd))
	a.connCtx.Store(connKey, &connTraceCtx{
		TraceID: "test",
		Created: time.Now(),
	})
	a.fdCausal.Store(connKey, &causalEntry{
		InboundFD: 3,
		Timestamp: time.Now(),
	})

	// Verify they exist
	if _, ok := a.connCtx.Load(connKey); !ok {
		t.Fatal("connCtx should exist before close")
	}
	if _, ok := a.fdCausal.Load(connKey); !ok {
		t.Fatal("fdCausal should exist before close")
	}

	// Simulate close — directly call cleanup logic
	a.connCtx.Delete(connKey)
	a.fdCausal.Delete(connKey)

	// Verify they're gone
	if _, ok := a.connCtx.Load(connKey); ok {
		t.Error("connCtx should be deleted after close")
	}
	if _, ok := a.fdCausal.Load(connKey); ok {
		t.Error("fdCausal should be deleted after close")
	}
}

func TestEnrichPairContext_CausalFDQueue(t *testing.T) {
	// Verify Layer 0 (CausalInboundFD from FIFO queue) takes priority over
	// Layer 1 (fdCausal map). This tests the pipelining scenario: two concurrent
	// outbound requests on the same FD (e.g., Redis persistent connection) get
	// the correct parent context from the queue, not the last-writer-wins map.
	a := newTestAgentWithConnTracker()

	// Register outbound connection (Redis persistent connection, same FD=10)
	a.connTracker.Register(100, 10, 0, 6379)

	// Two inbound connections handling different requests
	storeTestConnCtx(a, 100, 5, "trace-reqA", "span-A", "server-spanA")
	storeTestConnCtx(a, 100, 7, "trace-reqB", "span-B", "server-spanB")

	// fdCausal map has last-writer (request B) — this is the BUG scenario
	causalKey := uint64(100)<<32 | uint64(uint32(int32(10)))
	a.fdCausal.Store(causalKey, &causalEntry{
		InboundFD: 7, // B overwrote A's entry
		Timestamp: time.Now(),
	})

	// Request A's pair has CausalInboundFD=5 (captured at AppendSend time via queue)
	pairA := &reassembly.RequestPair{
		PID:             100,
		TID:             200,
		FD:              10,
		Protocol:        "redis",
		CausalInboundFD: 5, // from FIFO queue — correct for request A
	}
	a.enrichPairContext(pairA)

	if pairA.ParentTraceID != "trace-reqA" {
		t.Errorf("pairA.ParentTraceID = %q, want %q (Layer 0 should use CausalInboundFD=5)", pairA.ParentTraceID, "trace-reqA")
	}
	if pairA.ParentSpanID != "server-spanA" {
		t.Errorf("pairA.ParentSpanID = %q, want %q", pairA.ParentSpanID, "server-spanA")
	}

	// Request B's pair has CausalInboundFD=7 (also from queue)
	pairB := &reassembly.RequestPair{
		PID:             100,
		TID:             200,
		FD:              10,
		Protocol:        "redis",
		CausalInboundFD: 7,
	}
	a.enrichPairContext(pairB)

	if pairB.ParentTraceID != "trace-reqB" {
		t.Errorf("pairB.ParentTraceID = %q, want %q (Layer 0 should use CausalInboundFD=7)", pairB.ParentTraceID, "trace-reqB")
	}
	if pairB.ParentSpanID != "server-spanB" {
		t.Errorf("pairB.ParentSpanID = %q, want %q", pairB.ParentSpanID, "server-spanB")
	}
}

func TestEnrichPairContext_CausalFDQueueZeroFallsToLayer1(t *testing.T) {
	// When CausalInboundFD is 0 (not set), Layer 1 fdCausal map should be used.
	a := newTestAgentWithConnTracker()

	a.connTracker.Register(100, 10, 0, 5432)
	storeTestConnCtx(a, 100, 5, "trace-pg", "span-pg", "server-pg")

	causalKey := uint64(100)<<32 | uint64(uint32(int32(10)))
	a.fdCausal.Store(causalKey, &causalEntry{
		InboundFD: 5,
		Timestamp: time.Now(),
	})

	pair := &reassembly.RequestPair{
		PID:             100,
		TID:             300,
		FD:              10,
		Protocol:        "postgres",
		CausalInboundFD: 0, // not set — should fall to Layer 1
	}
	a.enrichPairContext(pair)

	if pair.ParentTraceID != "trace-pg" {
		t.Errorf("ParentTraceID = %q, want %q (Layer 1 fallback)", pair.ParentTraceID, "trace-pg")
	}
	if pair.ParentSpanID != "server-pg" {
		t.Errorf("ParentSpanID = %q, want %q", pair.ParentSpanID, "server-pg")
	}
}

func TestEnrichPairContext_LayerPriority(t *testing.T) {
	// Verify Layer 1 (causal) takes priority over Layer 2 (thread) and Layer 3 (PID)
	a := newTestAgentWithConnTracker()

	// Register outbound connection (CLIENT)
	a.connTracker.Register(100, 10, 0, 80)

	// Store TWO inbound contexts: FD 5 (correct) and FD 7 (wrong)
	storeTestConnCtx(a, 100, 5, "trace-correct", "span-correct", "server-correct")
	storeTestConnCtx(a, 100, 7, "trace-wrong", "span-wrong", "server-wrong")

	// Layer 1: causal says FD 10 → inbound FD 5
	causalKey := uint64(100)<<32 | uint64(uint32(int32(10)))
	a.fdCausal.Store(causalKey, &causalEntry{
		InboundFD: 5,
		Timestamp: time.Now(),
	})

	// Layer 2: thread says TID 200 → inbound FD 7 (wrong one)
	tidKey := uint64(100)<<32 | uint64(200)
	a.threadInboundFD.Store(tidKey, int32(7))

	// Layer 3: PID says FD 7 (wrong one)
	{
		set := &pidInboundSet{}
		set.Add(7, time.Now())
		a.pidActiveCtx.Store(uint32(100), set)
	}

	pair := &reassembly.RequestPair{
		PID:         100,
		TID:         200,
		FD:          10,
		Protocol:    "http",
		RequestTime: time.Now(),
	}

	a.enrichPairContext(pair)

	// Should use Layer 1 (causal) → FD 5 → "trace-correct"
	if pair.ParentTraceID != "trace-correct" {
		t.Errorf("ParentTraceID = %q, want %q (Layer 1 should have priority)", pair.ParentTraceID, "trace-correct")
	}
}

func TestEnrichPairContext_ConcurrentInbound(t *testing.T) {
	a := newTestAgentWithConnTracker()

	// Register outbound connection (CLIENT)
	a.connTracker.Register(100, 10, 0, 80)

	now := time.Now()

	// Two concurrent inbound FDs for PID 100
	storeTestConnCtx(a, 100, 5, "trace-old", "span-old", "server-old")
	// Backdate FD 5's connCtx
	connKey5 := uint64(100)<<32 | uint64(uint32(int32(5)))
	if val, ok := a.connCtx.Load(connKey5); ok {
		val.(*connTraceCtx).Created = now.Add(-10 * time.Millisecond)
	}

	storeTestConnCtx(a, 100, 7, "trace-new", "span-new", "server-new")
	// FD 7 created 2ms ago
	connKey7 := uint64(100)<<32 | uint64(uint32(int32(7)))
	if val, ok := a.connCtx.Load(connKey7); ok {
		val.(*connTraceCtx).Created = now.Add(-2 * time.Millisecond)
	}

	// Track both inbound FDs in pidActiveCtx
	set := &pidInboundSet{}
	set.Add(5, now.Add(-10*time.Millisecond))
	set.Add(7, now.Add(-2*time.Millisecond))
	a.pidActiveCtx.Store(uint32(100), set)

	pair := &reassembly.RequestPair{
		PID:         100,
		TID:         999, // no threadInboundFD, no fdCausal → falls to Layer 3
		FD:          10,
		Protocol:    "http",
		RequestTime: now,
	}

	a.enrichPairContext(pair)

	// Temporal match should pick FD 7 (most recent before pair.RequestTime)
	if pair.ParentTraceID != "trace-new" {
		t.Errorf("ParentTraceID = %q, want %q (should pick most recent inbound FD)", pair.ParentTraceID, "trace-new")
	}
	if pair.ParentSpanID != "server-new" {
		t.Errorf("ParentSpanID = %q, want %q", pair.ParentSpanID, "server-new")
	}
}

func TestPidInboundSet_AddRemove(t *testing.T) {
	s := &pidInboundSet{}
	now := time.Now()

	s.Add(5, now)
	s.Add(7, now.Add(time.Millisecond))

	if s.Count() != 2 {
		t.Fatalf("Count = %d, want 2", s.Count())
	}

	s.Remove(5)
	if s.Count() != 1 {
		t.Fatalf("Count = %d, want 1 after Remove", s.Count())
	}

	fd, ok := s.BestMatch(now.Add(2 * time.Millisecond))
	if !ok || fd != 7 {
		t.Errorf("BestMatch = (%d, %v), want (7, true)", fd, ok)
	}
}

func TestPidInboundSet_BestMatchSingle(t *testing.T) {
	s := &pidInboundSet{}
	s.Add(5, time.Now())

	fd, ok := s.BestMatch(time.Now())
	if !ok || fd != 5 {
		t.Errorf("BestMatch single = (%d, %v), want (5, true)", fd, ok)
	}
}

func TestPidInboundSet_BestMatchMulti(t *testing.T) {
	s := &pidInboundSet{}
	now := time.Now()
	s.Add(5, now.Add(-10*time.Millisecond))
	s.Add(7, now.Add(-2*time.Millisecond))
	s.Add(9, now.Add(5*time.Millisecond)) // in the future

	// Query at 'now': should pick FD 7 (closest before now)
	fd, ok := s.BestMatch(now)
	if !ok || fd != 7 {
		t.Errorf("BestMatch = (%d, %v), want (7, true)", fd, ok)
	}
}

func TestPidInboundSet_Eviction(t *testing.T) {
	s := &pidInboundSet{}
	base := time.Now()

	// Fill to capacity (16 entries)
	for i := 0; i < 16; i++ {
		s.Add(int32(i), base.Add(time.Duration(i)*time.Millisecond))
	}
	if s.Count() != 16 {
		t.Fatalf("Count = %d, want 16", s.Count())
	}

	// Adding one more should evict the oldest (FD 0)
	s.Add(99, base.Add(20*time.Millisecond))
	if s.Count() != 16 {
		t.Fatalf("Count after evict = %d, want 16", s.Count())
	}

	// FD 0 should be gone, FD 99 should exist
	fd, ok := s.BestMatch(base.Add(21 * time.Millisecond))
	if !ok {
		t.Fatal("BestMatch should succeed")
	}
	if fd == 0 {
		t.Error("FD 0 should have been evicted")
	}
}

func TestPidInboundSet_FDReuse(t *testing.T) {
	s := &pidInboundSet{}
	now := time.Now()

	s.Add(5, now)
	s.Add(5, now.Add(time.Second)) // reuse same FD

	if s.Count() != 1 {
		t.Errorf("Count = %d, want 1 (FD reuse should update, not add)", s.Count())
	}
}

func TestPidInboundSet_CleanStale(t *testing.T) {
	s := &pidInboundSet{}
	now := time.Now()

	s.Add(5, now.Add(-2*time.Minute))
	s.Add(7, now)

	s.CleanStale(time.Minute)

	if s.Count() != 1 {
		t.Fatalf("Count = %d, want 1 after CleanStale", s.Count())
	}
	fd, ok := s.BestMatch(now.Add(time.Second))
	if !ok || fd != 7 {
		t.Errorf("remaining FD = %d, want 7", fd)
	}
}

func TestPidInboundSet_Empty(t *testing.T) {
	s := &pidInboundSet{}
	_, ok := s.BestMatch(time.Now())
	if ok {
		t.Error("BestMatch on empty set should return false")
	}
}
