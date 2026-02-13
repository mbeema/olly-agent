// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
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

	return &MultilineAssembler{
		maxLines:     maxLines,
		flushTimeout: flushTimeout,
		emit:         emit,
	}
}

// Process takes a log record and either buffers it (continuation) or flushes
// the buffer and starts a new entry.
func (m *MultilineAssembler) Process(record *LogRecord) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if isContinuation(record.Body) && len(m.buffer) > 0 {
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

	return false
}
