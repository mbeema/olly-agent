// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mbeema/olly/pkg/config"
)

func TestIsContinuationLeadingWhitespace(t *testing.T) {
	tests := []struct {
		line string
		want bool
	}{
		{"  indented line", true},
		{"\tindented tab", true},
		{"normal line", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isContinuation(tt.line); got != tt.want {
			t.Errorf("isContinuation(%q) = %v, want %v", tt.line, got, tt.want)
		}
	}
}

func TestIsContinuationJavaStackTrace(t *testing.T) {
	lines := []string{
		"at com.example.MyClass.method(MyClass.java:42)",
		"Caused by: java.lang.NullPointerException",
		"... 23 more",
	}
	for _, line := range lines {
		if !isContinuation(line) {
			t.Errorf("expected %q to be continuation", line)
		}
	}
}

func TestIsContinuationPythonTraceback(t *testing.T) {
	lines := []string{
		"Traceback (most recent call last):",
		"File \"/app/main.py\", line 42, in handler",
	}
	for _, line := range lines {
		if !isContinuation(line) {
			t.Errorf("expected %q to be continuation", line)
		}
	}
}

func TestIsContinuationGoPanic(t *testing.T) {
	if !isContinuation("goroutine 1 [running]:") {
		t.Error("expected goroutine line to be continuation")
	}
}

func TestIsContinuationNormalLines(t *testing.T) {
	normal := []string{
		"2024-01-01 INFO Starting server",
		"ERROR: something failed",
		"[INFO] healthy",
	}
	for _, line := range normal {
		if isContinuation(line) {
			t.Errorf("expected %q to NOT be continuation", line)
		}
	}
}

func TestMultilineAssemblerJavaStackTrace(t *testing.T) {
	var mu sync.Mutex
	var results []*LogRecord

	cfg := &config.MultilineConfig{
		Enabled:      true,
		MaxLines:     100,
		FlushTimeout: 50 * time.Millisecond,
	}

	ma := NewMultilineAssembler(cfg, func(record *LogRecord) {
		mu.Lock()
		results = append(results, record)
		mu.Unlock()
	})

	// Java exception with stack trace
	ma.Process(&LogRecord{Body: "java.lang.RuntimeException: Connection refused"})
	ma.Process(&LogRecord{Body: "at com.example.Client.connect(Client.java:42)"})
	ma.Process(&LogRecord{Body: "at com.example.Main.run(Main.java:15)"})
	ma.Process(&LogRecord{Body: "Caused by: java.net.ConnectException: Connection refused"})
	ma.Process(&LogRecord{Body: "at java.net.Socket.connect(Socket.java:583)"})
	ma.Process(&LogRecord{Body: "... 5 more"})

	// New log entry triggers flush of previous
	ma.Process(&LogRecord{Body: "2024-01-01 INFO Server recovered"})

	// Wait for any timer flush
	time.Sleep(100 * time.Millisecond)
	ma.Flush()

	mu.Lock()
	defer mu.Unlock()

	if len(results) < 2 {
		t.Fatalf("expected at least 2 results, got %d", len(results))
	}

	// First result should be the joined stack trace
	stackTrace := results[0].Body
	if !strings.Contains(stackTrace, "java.lang.RuntimeException") {
		t.Error("stack trace should start with exception")
	}
	if !strings.Contains(stackTrace, "... 5 more") {
		t.Error("stack trace should contain '... 5 more'")
	}
	lines := strings.Count(stackTrace, "\n")
	if lines != 5 {
		t.Errorf("expected 5 newlines in joined stack trace, got %d", lines)
	}

	// Second result should be the normal log line
	if !strings.Contains(results[1].Body, "Server recovered") {
		t.Error("second result should be the normal log line")
	}
}

func TestMultilineAssemblerPythonTraceback(t *testing.T) {
	var mu sync.Mutex
	var results []*LogRecord

	cfg := &config.MultilineConfig{
		Enabled:      true,
		MaxLines:     100,
		FlushTimeout: 50 * time.Millisecond,
	}

	ma := NewMultilineAssembler(cfg, func(record *LogRecord) {
		mu.Lock()
		results = append(results, record)
		mu.Unlock()
	})

	ma.Process(&LogRecord{Body: "ERROR: Unhandled exception"})
	ma.Process(&LogRecord{Body: "Traceback (most recent call last):"})
	ma.Process(&LogRecord{Body: "  File \"/app/main.py\", line 42, in handler"})
	ma.Process(&LogRecord{Body: "    response = requests.get(url)"})
	// Flush via new entry
	ma.Process(&LogRecord{Body: "INFO: Request processed"})
	time.Sleep(100 * time.Millisecond)
	ma.Flush()

	mu.Lock()
	defer mu.Unlock()

	if len(results) < 2 {
		t.Fatalf("expected at least 2 results, got %d", len(results))
	}

	if !strings.Contains(results[0].Body, "Traceback") {
		t.Error("expected traceback in first result")
	}
}

func TestMultilineAssemblerNormalLinesPassThrough(t *testing.T) {
	var mu sync.Mutex
	var results []*LogRecord

	cfg := &config.MultilineConfig{
		Enabled:      true,
		MaxLines:     100,
		FlushTimeout: 50 * time.Millisecond,
	}

	ma := NewMultilineAssembler(cfg, func(record *LogRecord) {
		mu.Lock()
		results = append(results, record)
		mu.Unlock()
	})

	ma.Process(&LogRecord{Body: "2024-01-01 INFO line 1"})
	ma.Process(&LogRecord{Body: "2024-01-01 INFO line 2"})
	ma.Process(&LogRecord{Body: "2024-01-01 INFO line 3"})
	time.Sleep(100 * time.Millisecond)
	ma.Flush()

	mu.Lock()
	defer mu.Unlock()

	if len(results) != 3 {
		t.Errorf("expected 3 results for 3 normal lines, got %d", len(results))
	}
}

func TestMultilineAssemblerMaxLines(t *testing.T) {
	var mu sync.Mutex
	var results []*LogRecord

	cfg := &config.MultilineConfig{
		Enabled:      true,
		MaxLines:     3,
		FlushTimeout: 1 * time.Second, // long timeout to test maxLines trigger
	}

	ma := NewMultilineAssembler(cfg, func(record *LogRecord) {
		mu.Lock()
		results = append(results, record)
		mu.Unlock()
	})

	ma.Process(&LogRecord{Body: "Exception occurred"})
	ma.Process(&LogRecord{Body: "at line 1"})
	ma.Process(&LogRecord{Body: "at line 2"})

	// Should have flushed at maxLines=3
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(results) != 1 {
		t.Fatalf("expected 1 result after maxLines flush, got %d", len(results))
	}
	if !strings.Contains(results[0].Body, "at line 2") {
		t.Error("expected all lines in flushed result")
	}
}

func TestMultilineAssemblerFlushTimeout(t *testing.T) {
	var mu sync.Mutex
	var results []*LogRecord

	cfg := &config.MultilineConfig{
		Enabled:      true,
		MaxLines:     100,
		FlushTimeout: 50 * time.Millisecond,
	}

	ma := NewMultilineAssembler(cfg, func(record *LogRecord) {
		mu.Lock()
		results = append(results, record)
		mu.Unlock()
	})

	ma.Process(&LogRecord{Body: "Exception"})
	ma.Process(&LogRecord{Body: "at method()"})

	// Wait for flush timeout
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if len(results) != 1 {
		t.Fatalf("expected 1 result after timeout flush, got %d", len(results))
	}
}

func TestMultilineAssemblerDefaultConfig(t *testing.T) {
	cfg := &config.MultilineConfig{
		Enabled: true,
		// MaxLines and FlushTimeout left at zero to test defaults
	}

	emitted := false
	ma := NewMultilineAssembler(cfg, func(record *LogRecord) {
		emitted = true
	})

	if ma.maxLines != 100 {
		t.Errorf("expected default maxLines 100, got %d", ma.maxLines)
	}
	if ma.flushTimeout != 100*time.Millisecond {
		t.Errorf("expected default flushTimeout 100ms, got %v", ma.flushTimeout)
	}

	ma.Process(&LogRecord{Body: "test"})
	ma.Flush()
	if !emitted {
		t.Error("expected emit after flush")
	}
}
