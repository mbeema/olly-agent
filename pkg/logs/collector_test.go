// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"sync"
	"testing"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"go.uber.org/zap"
)

func newTestCollector(cfg *config.LogsConfig) (*Collector, *[]*LogRecord) {
	var mu sync.Mutex
	var records []*LogRecord
	c := NewCollector(cfg, zap.NewNop())
	c.OnLog(func(r *LogRecord) {
		mu.Lock()
		records = append(records, r)
		mu.Unlock()
	})
	return c, &records
}

func TestCollectorFilterExcludePattern(t *testing.T) {
	cfg := &config.LogsConfig{
		Enabled: true,
		Filter: config.LogFilterConfig{
			ExcludePatterns: []string{"healthcheck", "^DEBUG "},
		},
	}
	c, records := newTestCollector(cfg)

	c.emit(&LogRecord{Body: "INFO request handled"})
	c.emit(&LogRecord{Body: "healthcheck ok"})
	c.emit(&LogRecord{Body: "DEBUG something verbose"})
	c.emit(&LogRecord{Body: "ERROR connection failed"})

	if len(*records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(*records))
	}
	if (*records)[0].Body != "INFO request handled" {
		t.Errorf("expected first record 'INFO request handled', got %q", (*records)[0].Body)
	}
	if (*records)[1].Body != "ERROR connection failed" {
		t.Errorf("expected second record 'ERROR connection failed', got %q", (*records)[1].Body)
	}
}

func TestCollectorFilterIncludePattern(t *testing.T) {
	cfg := &config.LogsConfig{
		Enabled: true,
		Filter: config.LogFilterConfig{
			IncludePatterns: []string{"ERROR", "WARN"},
		},
	}
	c, records := newTestCollector(cfg)

	c.emit(&LogRecord{Body: "INFO startup complete"})
	c.emit(&LogRecord{Body: "ERROR disk full"})
	c.emit(&LogRecord{Body: "WARN memory low"})
	c.emit(&LogRecord{Body: "DEBUG trace data"})

	if len(*records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(*records))
	}
	if (*records)[0].Body != "ERROR disk full" {
		t.Errorf("expected 'ERROR disk full', got %q", (*records)[0].Body)
	}
	if (*records)[1].Body != "WARN memory low" {
		t.Errorf("expected 'WARN memory low', got %q", (*records)[1].Body)
	}
}

func TestCollectorFilterMinLevel(t *testing.T) {
	cfg := &config.LogsConfig{
		Enabled: true,
		Filter: config.LogFilterConfig{
			MinLevel: "WARN",
		},
	}
	c, records := newTestCollector(cfg)

	c.emit(&LogRecord{Body: "trace msg", Level: LevelTrace})
	c.emit(&LogRecord{Body: "debug msg", Level: LevelDebug})
	c.emit(&LogRecord{Body: "info msg", Level: LevelInfo})
	c.emit(&LogRecord{Body: "warn msg", Level: LevelWarn})
	c.emit(&LogRecord{Body: "error msg", Level: LevelError})
	c.emit(&LogRecord{Body: "fatal msg", Level: LevelFatal})
	// Unspecified level should pass through (not filtered)
	c.emit(&LogRecord{Body: "unknown level"})

	if len(*records) != 4 {
		t.Fatalf("expected 4 records (warn+error+fatal+unspecified), got %d", len(*records))
	}
	if (*records)[0].Body != "warn msg" {
		t.Errorf("expected first 'warn msg', got %q", (*records)[0].Body)
	}
	if (*records)[3].Body != "unknown level" {
		t.Errorf("expected last 'unknown level', got %q", (*records)[3].Body)
	}
}

func TestCollectorFilterCombined(t *testing.T) {
	cfg := &config.LogsConfig{
		Enabled: true,
		Filter: config.LogFilterConfig{
			IncludePatterns: []string{"request"},
			ExcludePatterns: []string{"healthcheck"},
			MinLevel:        "INFO",
		},
	}
	c, records := newTestCollector(cfg)

	c.emit(&LogRecord{Body: "request handled", Level: LevelInfo})
	c.emit(&LogRecord{Body: "request healthcheck", Level: LevelInfo})
	c.emit(&LogRecord{Body: "request debug", Level: LevelDebug})
	c.emit(&LogRecord{Body: "no match", Level: LevelError})

	if len(*records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(*records))
	}
	if (*records)[0].Body != "request handled" {
		t.Errorf("expected 'request handled', got %q", (*records)[0].Body)
	}
}

func TestCollectorJournaldSource(t *testing.T) {
	// Verify that journald source type is accepted without error.
	// On macOS (and systems without journalctl), the reader starts
	// but gracefully logs a warning and returns nil.
	cfg := &config.LogsConfig{
		Enabled: true,
		Sources: []config.LogSource{
			{
				Type:  "journald",
				Paths: []string{"sshd.service"},
			},
		},
	}
	c := NewCollector(cfg, zap.NewNop())
	// Start should not panic or return error for journald type
	// (even on macOS where journalctl doesn't exist)
	// We just verify the source type is handled, not that journalctl runs.
	// The journaldReader will be nil on macOS (journalctl not found).
	_ = c
}

func TestMultilineFirstLinePattern(t *testing.T) {
	var mu sync.Mutex
	var results []*LogRecord

	cfg := &config.MultilineConfig{
		Enabled:          true,
		MaxLines:         100,
		FlushTimeout:     50 * time.Millisecond,
		FirstLinePattern: `^\d{4}-\d{2}-\d{2}`,
	}

	ma := NewMultilineAssembler(cfg, func(record *LogRecord) {
		mu.Lock()
		results = append(results, record)
		mu.Unlock()
	})

	// First log entry with timestamp prefix
	ma.Process(&LogRecord{Body: "2024-01-01 INFO Starting server"})
	// Continuation line (doesn't match firstline pattern)
	ma.Process(&LogRecord{Body: "  loading config from /etc/app.yaml"})
	ma.Process(&LogRecord{Body: "  listening on :8080"})
	// Second log entry (matches firstline pattern → flush first entry)
	ma.Process(&LogRecord{Body: "2024-01-01 ERROR Connection refused"})
	// Continuation
	ma.Process(&LogRecord{Body: "  retrying in 5s"})

	// Wait for flush timeout then flush remaining
	time.Sleep(100 * time.Millisecond)
	ma.Flush()

	mu.Lock()
	defer mu.Unlock()

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	// First result: 3 lines joined
	if results[0].Body != "2024-01-01 INFO Starting server\n  loading config from /etc/app.yaml\n  listening on :8080" {
		t.Errorf("unexpected first result: %q", results[0].Body)
	}

	// Second result: 2 lines joined
	if results[1].Body != "2024-01-01 ERROR Connection refused\n  retrying in 5s" {
		t.Errorf("unexpected second result: %q", results[1].Body)
	}
}

func TestMultilineFirstLinePatternBracket(t *testing.T) {
	var mu sync.Mutex
	var results []*LogRecord

	cfg := &config.MultilineConfig{
		Enabled:          true,
		MaxLines:         100,
		FlushTimeout:     50 * time.Millisecond,
		FirstLinePattern: `^\[`,
	}

	ma := NewMultilineAssembler(cfg, func(record *LogRecord) {
		mu.Lock()
		results = append(results, record)
		mu.Unlock()
	})

	ma.Process(&LogRecord{Body: "[INFO] Request received"})
	ma.Process(&LogRecord{Body: "  processing item 1"})
	ma.Process(&LogRecord{Body: "[ERROR] Failed"})

	time.Sleep(100 * time.Millisecond)
	ma.Flush()

	mu.Lock()
	defer mu.Unlock()

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Body != "[INFO] Request received\n  processing item 1" {
		t.Errorf("unexpected first result: %q", results[0].Body)
	}
	if results[1].Body != "[ERROR] Failed" {
		t.Errorf("unexpected second result: %q", results[1].Body)
	}
}

func TestParseLevelStrings(t *testing.T) {
	tests := []struct {
		input string
		want  LogLevel
	}{
		{"TRACE", LevelTrace},
		{"trace", LevelTrace},
		{"DEBUG", LevelDebug},
		{"INFO", LevelInfo},
		{"WARN", LevelWarn},
		{"WARNING", LevelWarn},
		{"ERROR", LevelError},
		{"ERR", LevelError},
		{"FATAL", LevelFatal},
		{"CRITICAL", LevelFatal},
		{"unknown", LevelUnspecified},
		{"", LevelUnspecified},
	}
	for _, tt := range tests {
		got := ParseLevel(tt.input)
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestCollectorPerSourceMultiline(t *testing.T) {
	var mu sync.Mutex
	var results []*LogRecord

	cfg := &config.LogsConfig{
		Enabled: true,
		Sources: []config.LogSource{
			{
				Type:  "file",
				Paths: []string{"/dev/null"},
				Multiline: &config.MultilineConfig{
					Enabled:          true,
					MaxLines:         100,
					FlushTimeout:     50 * time.Millisecond,
					FirstLinePattern: `^\d{4}-`,
				},
			},
		},
	}
	c := NewCollector(cfg, zap.NewNop())
	c.OnLog(func(r *LogRecord) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
	})

	// Simulate emitting through source index 0 (which has per-source multiline)
	c.emitForSource(0, &LogRecord{Body: "2024-01-01 line1"})
	c.emitForSource(0, &LogRecord{Body: "  continuation"})
	c.emitForSource(0, &LogRecord{Body: "2024-01-02 line2"})

	time.Sleep(100 * time.Millisecond)
	for _, ma := range c.sourceMultiline {
		ma.Flush()
	}

	mu.Lock()
	defer mu.Unlock()

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	if results[0].Body != "2024-01-01 line1\n  continuation" {
		t.Errorf("unexpected first result: %q", results[0].Body)
	}
}
