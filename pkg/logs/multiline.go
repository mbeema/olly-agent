// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mbeema/olly/pkg/config"
)

// MultilineAssembler buffers continuation lines and joins them into single log entries.
type MultilineAssembler struct {
	maxLines     int
	flushTimeout time.Duration
	emit         func(*LogRecord)
	firstLineRE  *regexp.Regexp // If set, lines matching this regex start a new entry

	mu      sync.Mutex
	buffer  []*LogRecord
	timer   *time.Timer
}

// NewMultilineAssembler creates a new multiline log assembler.
func NewMultilineAssembler(cfg *config.MultilineConfig, emit func(*LogRecord)) *MultilineAssembler {
	maxLines := cfg.MaxLines
	if maxLines <= 0 {
		maxLines = 100
	}
	flushTimeout := cfg.FlushTimeout
	if flushTimeout <= 0 {
		flushTimeout = 100 * time.Millisecond
	}

	m := &MultilineAssembler{
		maxLines:     maxLines,
		flushTimeout: flushTimeout,
		emit:         emit,
	}
	if cfg.FirstLinePattern != "" {
		m.firstLineRE = regexp.MustCompile(cfg.FirstLinePattern)
	}
	return m
}

// Process takes a log record and either buffers it (continuation) or flushes
// the buffer and starts a new entry.
func (m *MultilineAssembler) Process(record *LogRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()

	isNewEntry := m.isNewEntry(record.Body)

	if !isNewEntry && len(m.buffer) > 0 {
		m.buffer = append(m.buffer, record)
		if len(m.buffer) >= m.maxLines {
			m.flushLocked()
		} else {
			m.resetTimerLocked()
		}
		return
	}

	// New log entry: flush previous buffer, start new
	if len(m.buffer) > 0 {
		m.flushLocked()
	}
	m.buffer = append(m.buffer, record)
	m.resetTimerLocked()
}

// isNewEntry returns true if the line starts a new log entry.
// When firstLineRE is set, a match means new entry.
// Otherwise, falls back to the heuristic: non-continuation = new entry.
func (m *MultilineAssembler) isNewEntry(line string) bool {
	if m.firstLineRE != nil {
		return m.firstLineRE.MatchString(line)
	}
	return !isContinuation(line)
}

// Flush emits any buffered log records as a single joined entry.
func (m *MultilineAssembler) Flush() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flushLocked()
}

func (m *MultilineAssembler) flushLocked() {
	if m.timer != nil {
		m.timer.Stop()
		m.timer = nil
	}
	if len(m.buffer) == 0 {
		return
	}

	// Join all lines into the first record
	first := m.buffer[0]
	if len(m.buffer) > 1 {
		var sb strings.Builder
		sb.WriteString(first.Body)
		for _, r := range m.buffer[1:] {
			sb.WriteByte('\n')
			sb.WriteString(r.Body)
		}
		first.Body = sb.String()
	}

	m.buffer = m.buffer[:0]
	m.emit(first)
}

func (m *MultilineAssembler) resetTimerLocked() {
	if m.timer != nil {
		m.timer.Stop()
	}
	m.timer = time.AfterFunc(m.flushTimeout, func() {
		m.Flush()
	})
}

// isContinuation returns true if the line looks like a continuation of a
// previous log entry (stack trace line, indented text, etc.).
func isContinuation(line string) bool {
	if len(line) == 0 {
		return false
	}

	// Leading whitespace (indented continuation)
	if line[0] == ' ' || line[0] == '\t' {
		return true
	}

	// Java stack trace patterns
	if strings.HasPrefix(line, "at ") {
		return true
	}
	if strings.HasPrefix(line, "Caused by:") {
		return true
	}
	if strings.HasPrefix(line, "... ") {
		return true
	}

	// Python traceback patterns
	if strings.HasPrefix(line, "Traceback (") {
		return true
	}
	if strings.HasPrefix(line, "File \"") {
		return true
	}

	// Go panic patterns
	if strings.HasPrefix(line, "goroutine ") {
		return true
	}

	// .NET stack trace patterns
	if strings.HasPrefix(line, "   at ") {
		return true
	}
	if strings.HasPrefix(line, "--->") {
		return true
	}
	if strings.HasPrefix(line, "Unhandled exception.") {
		return true
	}

	// Ruby stack trace patterns
	if strings.HasPrefix(line, "from ") {
		return true
	}

	// Rust panic/backtrace patterns
	if strings.HasPrefix(line, "thread '") {
		return true
	}
	if strings.HasPrefix(line, "stack backtrace:") {
		return true
	}
	if strings.HasPrefix(line, "note: ") {
		return true
	}

	// Elixir/Erlang stack trace patterns
	if strings.HasPrefix(line, "** (") {
		return true
	}
	if strings.HasPrefix(line, "    (") {
		return true
	}
	if strings.HasPrefix(line, "    lib/") {
		return true
	}

	return false
}
