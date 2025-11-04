package redact

import (
	"regexp"
	"strings"
)

// Rule defines a single redaction pattern.
type Rule struct {
	Name        string
	Pattern     *regexp.Regexp
	Replacement string
}

// Redactor applies a set of redaction rules to input strings.
type Redactor struct {
	rules   []Rule
	enabled bool
}

// New creates a Redactor with built-in rules. If enabled is false, Redact() is a no-op.
func New(enabled bool, extraRules []Rule) *Redactor {
	r := &Redactor{enabled: enabled}
	if !enabled {
		return r
	}
	r.rules = builtinRules()
	r.rules = append(r.rules, extraRules...)
	return r
}

// Redact applies all rules to the input string and returns the redacted result.
func (r *Redactor) Redact(input string) string {
	if !r.enabled || len(r.rules) == 0 {
		return input
	}
	result := input
	for _, rule := range r.rules {
		result = rule.Pattern.ReplaceAllString(result, rule.Replacement)
	}
	return result
}

// RedactMap applies redaction to selected map values.
func (r *Redactor) RedactMap(attrs map[string]string, keys ...string) {
	if !r.enabled {
		return
	}
	for _, k := range keys {
		if v, ok := attrs[k]; ok {
			attrs[k] = r.Redact(v)
		}
	}
}

func builtinRules() []Rule {
	return []Rule{
		{
			Name:        "credit_card",
			Pattern:     regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
			Replacement: "[REDACTED_CC]",
		},
		{
			Name:        "ssn",
			Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			Replacement: "[REDACTED_SSN]",
		},
		{
			Name:        "authorization_header",
			Pattern:     regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)\S+(\s+\S+)?`),
			Replacement: "${1}[REDACTED]",
		},
		{
			Name:        "password_param",
			Pattern:     regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token|api_key|apikey)\s*[=:]\s*['"]?[^\s&,;'"]+`),
			Replacement: "${1}=[REDACTED]",
		},
		{
			Name:        "password_in_sql",
			Pattern:     regexp.MustCompile(`(?i)(password\s*=\s*)'[^']*'`),
			Replacement: "${1}'[REDACTED]'",
		},
	}
}

// RedactHeaders redacts sensitive HTTP header values in a raw header block.
func RedactHeaders(headers string) string {
	sensitiveHeaders := []string{"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
	lines := strings.Split(headers, "\r\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, h := range sensitiveHeaders {
			if strings.HasPrefix(lower, h+":") {
				colonIdx := strings.Index(line, ":")
				if colonIdx >= 0 {
					lines[i] = line[:colonIdx+1] + " [REDACTED]"
				}
			}
		}
	}
	return strings.Join(lines, "\r\n")
}
