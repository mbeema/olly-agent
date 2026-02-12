// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/mbeema/olly/pkg/config"
)

// SecurityEventType classifies security-relevant events.
type SecurityEventType string

const (
	SecurityLogin          SecurityEventType = "authentication.login"
	SecurityLoginFailed    SecurityEventType = "authentication.login_failed"
	SecurityLogout         SecurityEventType = "authentication.logout"
	SecurityPrivEscalation SecurityEventType = "privilege.escalation"
	SecuritySudo           SecurityEventType = "privilege.sudo"
	SecurityFileAccess     SecurityEventType = "file.access"
	SecurityUserChange     SecurityEventType = "user.change"
	SecurityGroupChange    SecurityEventType = "group.change"
	SecurityServiceChange  SecurityEventType = "service.change"
	SecurityNetworkChange  SecurityEventType = "network.change"
	SecurityAuditGeneric   SecurityEventType = "audit.generic"
)

// AuditParser parses Linux audit log formats (auditd, auth.log, secure).
// Supports:
//   - /var/log/audit/audit.log (auditd native format)
//   - /var/log/auth.log, /var/log/secure (syslog auth format)
type AuditParser struct {
	auditRe *regexp.Regexp
	authRe  *regexp.Regexp
	kvRe    *regexp.Regexp
}

// NewAuditParser creates a new audit log parser.
func NewAuditParser() *AuditParser {
	return &AuditParser{
		// auditd format: type=X msg=audit(EPOCH:SERIAL): key=value ...
		auditRe: regexp.MustCompile(`type=(\S+)\s+msg=audit\((\d+)\.\d+:\d+\):\s*(.*)`),
		// auth.log format: Mon DD HH:MM:SS hostname program[pid]: message
		authRe: regexp.MustCompile(`^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)`),
		// Key-value pairs in audit messages
		kvRe: regexp.MustCompile(`(\w+)=("(?:[^"\\]|\\.)*"|\S+)`),
	}
}

// ParseAuditLine parses a single line from /var/log/audit/audit.log.
func (p *AuditParser) ParseAuditLine(line string) *LogRecord {
	matches := p.auditRe.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	auditType := matches[1]
	epochStr := matches[2]
	body := matches[3]

	// Parse timestamp
	epoch, _ := strconv.ParseInt(epochStr, 10, 64)
	ts := time.Unix(epoch, 0)

	// Parse key-value pairs
	attrs := make(map[string]interface{})
	attrs["audit.type"] = auditType

	kvMatches := p.kvRe.FindAllStringSubmatch(body, -1)
	for _, kv := range kvMatches {
		key := kv[1]
		value := strings.Trim(kv[2], "\"")
		attrs["audit."+key] = value
	}

	// Classify security event
	eventType := classifyAuditEvent(auditType, attrs)
	attrs["security.event_type"] = string(eventType)

	level := LevelInfo
	if isSecurityAlert(eventType) {
		level = LevelWarn
	}

	return &LogRecord{
		Timestamp:  ts,
		Body:       line,
		Level:      level,
		Attributes: attrs,
		Source:     "audit",
	}
}

// ParseAuthLine parses a single line from /var/log/auth.log or /var/log/secure.
func (p *AuditParser) ParseAuthLine(line string) *LogRecord {
	matches := p.authRe.FindStringSubmatch(line)
	if matches == nil {
		return nil
	}

	tsStr := matches[1]
	hostname := matches[2]
	program := matches[3]
	pidStr := matches[4]
	message := matches[5]

	// Parse syslog timestamp (assumes current year)
	ts := parseSyslogTimestamp(tsStr)

	attrs := make(map[string]interface{})
	attrs["host.name"] = hostname
	attrs["process.name"] = program
	if pidStr != "" {
		if pid, err := strconv.Atoi(pidStr); err == nil {
			attrs["process.pid"] = pid
		}
	}

	// Classify the auth event
	eventType := classifyAuthEvent(program, message)
	attrs["security.event_type"] = string(eventType)

	// Extract additional fields from common patterns
	enrichAuthAttrs(message, attrs)

	level := LevelInfo
	if isSecurityAlert(eventType) {
		level = LevelWarn
	}

	pid := 0
	if pidStr != "" {
		pid, _ = strconv.Atoi(pidStr)
	}

	return &LogRecord{
		Timestamp:   ts,
		Body:        message,
		Level:       level,
		Attributes:  attrs,
		PID:         pid,
		ProcessName: program,
		Source:      "auth",
	}
}

// classifyAuditEvent maps auditd type codes to security event types.
func classifyAuditEvent(auditType string, attrs map[string]interface{}) SecurityEventType {
	switch auditType {
	case "USER_LOGIN":
		if res, ok := attrs["audit.res"]; ok && res == "failed" {
			return SecurityLoginFailed
		}
		return SecurityLogin
	case "USER_LOGOUT":
		return SecurityLogout
	case "USER_AUTH":
		if res, ok := attrs["audit.res"]; ok && res == "failed" {
			return SecurityLoginFailed
		}
		return SecurityLogin
	case "CRED_ACQ", "CRED_DISP":
		return SecurityLogin
	case "USER_ACCT":
		return SecurityUserChange
	case "ADD_USER", "DEL_USER", "USER_MGMT":
		return SecurityUserChange
	case "ADD_GROUP", "DEL_GROUP", "GRP_MGMT":
		return SecurityGroupChange
	case "USER_CMD":
		return SecuritySudo
	case "EXECVE":
		return SecurityAuditGeneric
	case "PATH", "OPENAT":
		return SecurityFileAccess
	case "SERVICE_START", "SERVICE_STOP":
		return SecurityServiceChange
	case "NETFILTER_CFG":
		return SecurityNetworkChange
	default:
		return SecurityAuditGeneric
	}
}

// classifyAuthEvent maps auth.log messages to security event types.
func classifyAuthEvent(program, message string) SecurityEventType {
	msgLower := strings.ToLower(message)

	switch {
	case strings.Contains(program, "sshd"):
		switch {
		case strings.Contains(msgLower, "accepted"):
			return SecurityLogin
		case strings.Contains(msgLower, "failed"):
			return SecurityLoginFailed
		case strings.Contains(msgLower, "invalid user"):
			return SecurityLoginFailed
		case strings.Contains(msgLower, "disconnected"):
			return SecurityLogout
		}
	case strings.Contains(program, "sudo"):
		return SecuritySudo
	case strings.Contains(program, "su"):
		if strings.Contains(msgLower, "failed") || strings.Contains(msgLower, "authentication failure") {
			return SecurityLoginFailed
		}
		return SecurityPrivEscalation
	case strings.Contains(program, "useradd"), strings.Contains(program, "userdel"),
		strings.Contains(program, "usermod"), strings.Contains(program, "passwd"):
		return SecurityUserChange
	case strings.Contains(program, "groupadd"), strings.Contains(program, "groupdel"),
		strings.Contains(program, "groupmod"):
		return SecurityGroupChange
	case strings.Contains(program, "systemd"):
		if strings.Contains(msgLower, "started") || strings.Contains(msgLower, "stopped") {
			return SecurityServiceChange
		}
	}

	if strings.Contains(msgLower, "authentication failure") || strings.Contains(msgLower, "failed password") {
		return SecurityLoginFailed
	}

	return SecurityAuditGeneric
}

// enrichAuthAttrs extracts common fields from auth messages.
func enrichAuthAttrs(message string, attrs map[string]interface{}) {
	msgLower := strings.ToLower(message)

	// Extract user from common patterns
	userPatterns := []struct {
		prefix string
		key    string
	}{
		{"for user ", "user.name"},
		{"for ", "user.name"},
		{"user=", "user.name"},
		{"user ", "user.name"},
	}
	for _, p := range userPatterns {
		if idx := strings.Index(msgLower, p.prefix); idx >= 0 {
			rest := message[idx+len(p.prefix):]
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				attrs[p.key] = fields[0]
				break
			}
		}
	}

	// Extract source IP from SSH messages
	if idx := strings.Index(msgLower, "from "); idx >= 0 {
		rest := message[idx+5:]
		fields := strings.Fields(rest)
		if len(fields) > 0 {
			ip := fields[0]
			// Basic IP validation
			if strings.Count(ip, ".") == 3 || strings.Contains(ip, ":") {
				attrs["source.ip"] = ip
			}
		}
	}
}

// isSecurityAlert returns true for event types that warrant elevated severity.
func isSecurityAlert(eventType SecurityEventType) bool {
	switch eventType {
	case SecurityLoginFailed, SecurityPrivEscalation:
		return true
	default:
		return false
	}
}

// parseSyslogTimestamp parses "Jan  2 15:04:05" format, assuming current year.
func parseSyslogTimestamp(s string) time.Time {
	now := time.Now()
	// Try standard syslog format
	t, err := time.Parse("Jan  2 15:04:05", s)
	if err != nil {
		t, err = time.Parse("Jan 2 15:04:05", s)
		if err != nil {
			return now
		}
	}
	// Set year to current year
	return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
}

// DefaultSecurityLogSources returns pre-configured log sources for security/audit logs.
// These are the standard locations on Linux distributions.
func DefaultSecurityLogSources() []config.LogSource {
	return []config.LogSource{
		{
			Type:   "audit",
			Paths:  []string{"/var/log/audit/audit.log"},
			Format: "audit",
		},
		{
			Type:   "auth",
			Paths:  []string{"/var/log/auth.log", "/var/log/secure"},
			Format: "auth",
		},
	}
}
