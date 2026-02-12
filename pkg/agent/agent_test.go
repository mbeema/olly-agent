// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package agent

import (
	"testing"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/logs"
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
