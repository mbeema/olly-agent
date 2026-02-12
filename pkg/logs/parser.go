// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Parser detects and parses log formats.
type Parser struct {
	syslogRe   *regexp.Regexp
	combinedRe *regexp.Regexp
	pidRe      *regexp.Regexp
	tidRe      *regexp.Regexp
}

// NewParser creates a new log parser.
func NewParser() *Parser {
	return &Parser{
		// Syslog: "Jan  2 15:04:05 hostname process[pid]: message"
		syslogRe: regexp.MustCompile(
			`^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)$`,
		),
		// Combined (nginx/apache): `127.0.0.1 - - [02/Jan/2006:15:04:05 -0700] "GET /path HTTP/1.1" 200 1234`
		combinedRe: regexp.MustCompile(
			`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\d+)`,
		),
		// PID patterns: "pid=123", "PID 123", "process=123", "Process-123", "[pid:123]"
		pidRe: regexp.MustCompile(
			`(?i)(?:pid[=: ]|process[=: -])(\d+)`,
		),
		// TID patterns: "tid=456", "TID 456", "thread[=: -]456", "thread_id=456"
		tidRe: regexp.MustCompile(
			`(?i)(?:tid[=: ]|thread(?:_id)?[=: -])(\d+)`,
		),
	}
}

// Parse parses a log line into a LogRecord.
func (p *Parser) Parse(line string, format string) *LogRecord {
	switch format {
	case "json":
		return p.parseJSON(line)
	case "syslog":
		return p.parseSyslog(line)
	case "combined":
		return p.parseCombined(line)
	default:
		// Auto-detect
		return p.autoDetect(line)
	}
}

func (p *Parser) autoDetect(line string) *LogRecord {
	line = strings.TrimSpace(line)

	// Try JSON first
	if len(line) > 0 && line[0] == '{' {
		if record := p.parseJSON(line); record.Attributes != nil {
			return record
		}
	}

	// Try syslog
	if record := p.parseSyslog(line); record.ProcessName != "" {
		return record
	}

	// Try combined
	if record := p.parseCombined(line); record.Attributes != nil && record.Attributes["http.method"] != nil {
		return record
	}

	// Fallback: plain text
	record := &LogRecord{
		Timestamp:  time.Now(),
		Body:       line,
		Level:      detectLevel(line),
		Attributes: make(map[string]interface{}),
	}

	// Extract PID/TID from log content for correlation
	p.extractPIDTID(record, line)

	return record
}

func (p *Parser) parseJSON(line string) *LogRecord {
	record := &LogRecord{
		Timestamp:  time.Now(),
		Attributes: make(map[string]interface{}),
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		record.Body = line
		return record
	}

	// Extract well-known fields
	if ts, ok := extractString(data, "timestamp", "time", "ts", "@timestamp"); ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			record.Timestamp = t
		} else if t, err := time.Parse(time.RFC3339, ts); err == nil {
			record.Timestamp = t
		}
	}

	if msg, ok := extractString(data, "message", "msg", "body", "log"); ok {
		record.Body = msg
	} else {
		record.Body = line
	}

	if level, ok := extractString(data, "level", "severity", "lvl"); ok {
		record.Level = parseLevel(level)
	}

	if pid, ok := extractInt(data, "pid"); ok {
		record.PID = pid
	}

	if tid, ok := extractInt(data, "tid", "thread_id"); ok {
		record.TID = tid
	}

	// Extract trace context
	if traceID, ok := extractString(data, "trace_id", "traceId", "traceID"); ok {
		record.TraceID = traceID
	}
	if spanID, ok := extractString(data, "span_id", "spanId", "spanID"); ok {
		record.SpanID = spanID
	}

	// Store remaining fields as attributes
	for k, v := range data {
		record.Attributes[k] = v
	}

	return record
}

func (p *Parser) parseSyslog(line string) *LogRecord {
	record := &LogRecord{
		Timestamp:  time.Now(),
		Body:       line,
		Attributes: make(map[string]interface{}),
	}

	matches := p.syslogRe.FindStringSubmatch(line)
	if matches == nil {
		return record
	}

	// Parse timestamp (current year assumed)
	if ts, err := time.Parse("Jan  2 15:04:05", matches[1]); err == nil {
		ts = ts.AddDate(time.Now().Year(), 0, 0)
		record.Timestamp = ts
	}

	record.Attributes["hostname"] = matches[2]
	record.ProcessName = matches[3]

	if matches[4] != "" {
		if pid, err := strconv.Atoi(matches[4]); err == nil {
			record.PID = pid
		}
	}

	record.Body = matches[5]
	record.Level = detectLevel(record.Body)

	// Syslog extracts PID from header; also try TID from message body
	if record.TID == 0 {
		if m := p.tidRe.FindStringSubmatch(record.Body); m != nil {
			if tid, err := strconv.Atoi(m[1]); err == nil {
				record.TID = tid
			}
		}
	}

	return record
}

func (p *Parser) parseCombined(line string) *LogRecord {
	record := &LogRecord{
		Timestamp:  time.Now(),
		Body:       line,
		Attributes: make(map[string]interface{}),
	}

	matches := p.combinedRe.FindStringSubmatch(line)
	if matches == nil {
		return record
	}

	record.Attributes["net.peer.ip"] = matches[1]

	if ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", matches[2]); err == nil {
		record.Timestamp = ts
	}

	// Parse request line "GET /path HTTP/1.1"
	parts := strings.SplitN(matches[3], " ", 3)
	if len(parts) >= 2 {
		record.Attributes["http.method"] = parts[0]
		record.Attributes["http.target"] = parts[1]
	}

	statusCode, _ := strconv.Atoi(matches[4])
	record.Attributes["http.status_code"] = statusCode

	bodySize, _ := strconv.Atoi(matches[5])
	record.Attributes["http.response_content_length"] = bodySize

	record.Level = LevelInfo
	if statusCode >= 500 {
		record.Level = LevelError
	} else if statusCode >= 400 {
		record.Level = LevelWarn
	}

	return record
}

// extractPIDTID attempts to extract PID and TID from a log line.
// Handles common patterns: "pid=123", "PID 123", "process=123",
// "tid=456", "thread=456", "thread_id=456".
func (p *Parser) extractPIDTID(record *LogRecord, line string) {
	if record.PID == 0 {
		if m := p.pidRe.FindStringSubmatch(line); m != nil {
			if pid, err := strconv.Atoi(m[1]); err == nil {
				record.PID = pid
			}
		}
	}
	if record.TID == 0 {
		if m := p.tidRe.FindStringSubmatch(line); m != nil {
			if tid, err := strconv.Atoi(m[1]); err == nil {
				record.TID = tid
			}
		}
	}
}

// detectLevel infers log level from message content.
func detectLevel(msg string) LogLevel {
	upper := strings.ToUpper(msg)

	// Check for level keywords
	for _, pattern := range []struct {
		keyword string
		level   LogLevel
	}{
		{"FATAL", LevelFatal},
		{"PANIC", LevelFatal},
		{"ERROR", LevelError},
		{"ERR ", LevelError},
		{"WARN", LevelWarn},
		{"WARNING", LevelWarn},
		{"INFO", LevelInfo},
		{"DEBUG", LevelDebug},
		{"TRACE", LevelTrace},
	} {
		if strings.Contains(upper, pattern.keyword) {
			return pattern.level
		}
	}

	return LevelInfo
}

func parseLevel(s string) LogLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "TRACE":
		return LevelTrace
	case "DEBUG":
		return LevelDebug
	case "INFO", "INFORMATION":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR", "ERR":
		return LevelError
	case "FATAL", "CRITICAL", "PANIC":
		return LevelFatal
	default:
		return LevelUnspecified
	}
}

func extractString(data map[string]interface{}, keys ...string) (string, bool) {
	for _, k := range keys {
		if v, ok := data[k]; ok {
			if s, ok := v.(string); ok {
				return s, true
			}
		}
	}
	return "", false
}

func extractInt(data map[string]interface{}, keys ...string) (int, bool) {
	for _, k := range keys {
		if v, ok := data[k]; ok {
			switch n := v.(type) {
			case float64:
				return int(n), true
			case int:
				return n, true
			case int64:
				return int(n), true
			}
		}
	}
	return 0, false
}
