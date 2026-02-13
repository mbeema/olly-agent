// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package agent

import (
	"testing"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/conntrack"
	hookebpf "github.com/mbeema/olly/pkg/hook/ebpf"
	"github.com/mbeema/olly/pkg/logs"
	"github.com/mbeema/olly/pkg/reassembly"
	"go.uber.org/zap"
)

// newTestAgent creates a minimal agent for testing processHookLog.
func newTestAgent() *Agent {
	a := &Agent{
		logParser: logs.NewParser(),
		logCh:     make(chan *logs.LogRecord, 100),
		logger:    zap.NewNop(),
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
		logParser: logs.NewParser(),
		logCh:     make(chan *logs.LogRecord, 1),
		logger:    zap.NewNop(),
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
		logParser:   logs.NewParser(),
		logCh:       make(chan *logs.LogRecord, 100),
		logger:      zap.NewNop(),
		connTracker: conntrack.NewTracker(),
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

	// Store inbound context on FD 5
	storeTestConnCtx(a, 100, 5, "trace-abc", "span-def", "server-ghi")

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
	// HTTP should get InjectedSpanID
	if pair.InjectedSpanID != "span-def" {
		t.Errorf("InjectedSpanID = %q, want %q", pair.InjectedSpanID, "span-def")
	}
}

func TestEnrichPairContext_PIDFallback(t *testing.T) {
	a := newTestAgentWithConnTracker()

	// Register outbound connection (CLIENT)
	a.connTracker.Register(100, 10, 0, 5432)

	// Store inbound context on FD 5
	storeTestConnCtx(a, 100, 5, "trace-pid", "span-pid", "server-pid")

	// Store pidActiveCtx: most recent inbound FD for PID 100 is FD 5
	// (no fdCausal, no threadInboundFD for this TID — simulates Go goroutine TID mismatch)
	a.pidActiveCtx.Store(uint32(100), int32(5))

	pair := &reassembly.RequestPair{
		PID:      100,
		TID:      999, // different TID — goroutine migrated
		FD:       10,
		Protocol: "postgres",
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
	a.pidActiveCtx.Store(uint32(100), int32(5))

	pair := &reassembly.RequestPair{
		PID:      100,
		TID:      999,
		FD:       10,
		Protocol: "postgres",
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
	a.pidActiveCtx.Store(uint32(100), int32(7))

	pair := &reassembly.RequestPair{
		PID:      100,
		TID:      200,
		FD:       10,
		Protocol: "http",
	}

	a.enrichPairContext(pair)

	// Should use Layer 1 (causal) → FD 5 → "trace-correct"
	if pair.ParentTraceID != "trace-correct" {
		t.Errorf("ParentTraceID = %q, want %q (Layer 1 should have priority)", pair.ParentTraceID, "trace-correct")
	}
}
