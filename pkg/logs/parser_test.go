// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"testing"
)

func TestParseJSON(t *testing.T) {
	p := NewParser()

	line := `{"timestamp":"2024-01-15T10:30:00Z","level":"error","message":"connection failed","pid":1234,"trace_id":"abc123"}`
	record := p.Parse(line, "json")

	if record.Body != "connection failed" {
		t.Errorf("body = %q, want 'connection failed'", record.Body)
	}
	if record.Level != LevelError {
		t.Errorf("level = %v, want ERROR", record.Level)
	}
	if record.PID != 1234 {
		t.Errorf("pid = %d, want 1234", record.PID)
	}
	if record.TraceID != "abc123" {
		t.Errorf("traceID = %q, want 'abc123'", record.TraceID)
	}
}

func TestParseSyslog(t *testing.T) {
	p := NewParser()

	line := "Jan 15 10:30:00 myhost nginx[1234]: GET /api 200"
	record := p.Parse(line, "syslog")

	if record.ProcessName != "nginx" {
		t.Errorf("processName = %q, want 'nginx'", record.ProcessName)
	}
	if record.PID != 1234 {
		t.Errorf("pid = %d, want 1234", record.PID)
	}
	if record.Body != "GET /api 200" {
		t.Errorf("body = %q, want 'GET /api 200'", record.Body)
	}
}

func TestParseCombined(t *testing.T) {
	p := NewParser()

	line := `192.168.1.1 - - [15/Jan/2024:10:30:00 +0000] "POST /api/users HTTP/1.1" 201 45`
	record := p.Parse(line, "combined")

	if record.Attributes["http.method"] != "POST" {
		t.Errorf("method = %v, want POST", record.Attributes["http.method"])
	}
	if record.Attributes["http.target"] != "/api/users" {
		t.Errorf("target = %v, want /api/users", record.Attributes["http.target"])
	}
}

func TestAutoDetect(t *testing.T) {
	p := NewParser()

	// JSON
	json := `{"message":"test","level":"info"}`
	r := p.Parse(json, "auto")
	if r.Body != "test" {
		t.Errorf("JSON auto-detect failed: body = %q", r.Body)
	}

	// Plain text
	plain := "ERROR: something went wrong"
	r = p.Parse(plain, "auto")
	if r.Level != LevelError {
		t.Errorf("level detection failed: %v", r.Level)
	}
}

func TestExtractPIDTID(t *testing.T) {
	p := NewParser()

	tests := []struct {
		name      string
		line      string
		expectPID int
		expectTID int
	}{
		{"pid=N", "2024-01-15 ERROR pid=1234 tid=5678 connection failed", 1234, 5678},
		{"PID N", "PID 42 TID 99 starting worker", 42, 99},
		{"process=N thread=N", "process=100 thread=200 handling request", 100, 200},
		{"thread_id=N", "pid=55 thread_id=66 query complete", 55, 66},
		{"syslog with tid in body", "Jan 15 10:30:00 host app[999]: thread=77 processing", 999, 77},
		{"no pid/tid", "just a plain log message", 0, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := p.Parse(tt.line, "auto")
			if record.PID != tt.expectPID {
				t.Errorf("PID = %d, want %d", record.PID, tt.expectPID)
			}
			if record.TID != tt.expectTID {
				t.Errorf("TID = %d, want %d", record.TID, tt.expectTID)
			}
		})
	}
}

func TestDetectLevel(t *testing.T) {
	tests := []struct {
		msg    string
		expect LogLevel
	}{
		{"FATAL: system crash", LevelFatal},
		{"ERROR connecting to database", LevelError},
		{"WARNING: disk space low", LevelWarn},
		{"INFO: server started", LevelInfo},
		{"DEBUG: cache hit", LevelDebug},
		{"just a regular message", LevelInfo},
	}

	for _, tt := range tests {
		got := detectLevel(tt.msg)
		if got != tt.expect {
			t.Errorf("detectLevel(%q) = %v, want %v", tt.msg, got, tt.expect)
		}
	}
}
