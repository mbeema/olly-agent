// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// HTTPParser parses HTTP/1.1 request/response pairs.
type HTTPParser struct{}

func (p *HTTPParser) Name() string { return ProtoHTTP }

func (p *HTTPParser) Detect(data []byte, port uint16) bool {
	if len(data) < 4 {
		return false
	}

	s := string(data[:min(len(data), 16)])

	// Request detection
	if isHTTPMethod(s) {
		return true
	}

	// Response detection
	if strings.HasPrefix(s, "HTTP/") {
		return true
	}

	// Port-based fallback
	switch port {
	case 80, 443, 8080, 8443, 3000, 5000, 8000, 9090:
		// Check if it looks like text (not binary)
		for _, b := range data[:min(len(data), 32)] {
			if b < 0x20 && b != '\r' && b != '\n' && b != '\t' {
				return false
			}
		}
		return isHTTPMethod(s) || strings.HasPrefix(s, "HTTP/")
	}

	return false
}

func (p *HTTPParser) Parse(request, response []byte) (*SpanAttributes, error) {
	attrs := &SpanAttributes{
		Protocol: ProtoHTTP,
	}

	// Parse request
	if len(request) > 0 {
		req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(request)))
		if err == nil {
			attrs.HTTPMethod = req.Method
			attrs.HTTPPath = req.URL.Path
			attrs.HTTPQuery = req.URL.RawQuery
			attrs.HTTPHost = req.Host
			attrs.HTTPUserAgent = req.UserAgent()
			attrs.ContentLength = req.ContentLength // H8 fix: request content length
			req.Body.Close()
		} else {
			// Fallback: parse first line manually
			if idx := bytes.Index(request, []byte("\r\n")); idx > 0 {
				line := string(request[:idx])
				parts := strings.SplitN(line, " ", 3)
				if len(parts) >= 2 {
					attrs.HTTPMethod = parts[0]
					attrs.HTTPPath = parts[1]
				}
			}
		}
	}

	// Parse response
	if len(response) > 0 {
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(response)), nil)
		if err == nil {
			attrs.HTTPStatusCode = resp.StatusCode
			// H8 fix: don't overwrite request ContentLength with response
			resp.Body.Close()
		} else {
			// Fallback: parse status line
			if idx := bytes.Index(response, []byte("\r\n")); idx > 0 {
				line := string(response[:idx])
				parts := strings.SplitN(line, " ", 3)
				if len(parts) >= 2 {
					code, _ := strconv.Atoi(parts[1])
					attrs.HTTPStatusCode = code
				}
			}
		}
	}

	// Build span name per OTEL semantic conventions:
	// HTTP SERVER: "{method} {http.route}" — we use path since routes aren't available
	// HTTP CLIENT: "{method}"
	if attrs.HTTPMethod != "" && attrs.HTTPPath != "" {
		attrs.Name = attrs.HTTPMethod + " " + attrs.HTTPPath
	} else if attrs.HTTPMethod != "" {
		attrs.Name = attrs.HTTPMethod
	} else {
		attrs.Name = "HTTP"
	}
	if attrs.HTTPStatusCode >= 400 {
		attrs.Error = true
		attrs.ErrorMsg = fmt.Sprintf("HTTP %d", attrs.HTTPStatusCode)
	}

	return attrs, nil
}

// TraceContext holds extracted W3C trace context headers.
type TraceContext struct {
	TraceID    string
	SpanID     string
	Sampled    bool
	TraceState string // R1.2: W3C tracestate header value
}

// ExtractTraceParent extracts W3C traceparent header from HTTP request bytes.
func ExtractTraceParent(request []byte) (traceID, spanID string, sampled bool) {
	ctx := ExtractTraceContext(request)
	return ctx.TraceID, ctx.SpanID, ctx.Sampled
}

// ExtractTraceContext extracts both traceparent and tracestate from HTTP request bytes.
// B12 fix: uses case-insensitive search instead of bytes.ToLower (avoids full buffer copy on hot path).
func ExtractTraceContext(request []byte) TraceContext {
	var ctx TraceContext

	// Look for traceparent header (case-insensitive, zero-alloc)
	needle := []byte("traceparent: ")
	idx := indexBytesCI(request, needle)
	if idx < 0 {
		return ctx
	}

	// Extract traceparent value until \r\n
	start := idx + len(needle)
	end := bytes.Index(request[start:], []byte("\r\n"))
	if end < 0 {
		end = len(request) - start
	}
	value := strings.TrimSpace(string(request[start : start+end]))

	// Parse: 00-<traceID>-<spanID>-<flags>
	// Accept partial values (at least version + traceID) to handle BPF
	// MAX_CAPTURE truncation where spanID/flags may be cut off.
	parts := strings.Split(value, "-")
	if len(parts) < 2 || len(parts[1]) != 32 {
		return ctx
	}

	ctx.TraceID = parts[1]
	if len(parts) >= 3 && len(parts[2]) == 16 {
		ctx.SpanID = parts[2]
	}
	if len(parts) >= 4 {
		flags, _ := strconv.ParseInt(parts[3], 16, 64)
		ctx.Sampled = (flags & 0x01) != 0
	}

	// R1.2: Look for tracestate header
	tsNeedle := []byte("tracestate: ")
	tsIdx := indexBytesCI(request, tsNeedle)
	if tsIdx >= 0 {
		tsStart := tsIdx + len(tsNeedle)
		tsEnd := bytes.Index(request[tsStart:], []byte("\r\n"))
		if tsEnd < 0 {
			tsEnd = len(request) - tsStart
		}
		ctx.TraceState = strings.TrimSpace(string(request[tsStart : tsStart+tsEnd]))
	}

	return ctx
}

// NormalizeRoute collapses dynamic path segments to produce an http.route.
// Numeric IDs, UUIDs, and hex strings are replaced with {id}.
// Example: /api/users/42/orders/abc123 → /api/users/{id}/orders/{id}
func NormalizeRoute(path string) string {
	if path == "" || path == "/" {
		return path
	}
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		if isDynamicSegment(seg) {
			segments[i] = "{id}"
		}
	}
	return strings.Join(segments, "/")
}

// isDynamicSegment returns true if a path segment looks like a dynamic value
// (numeric ID, UUID, or long hex string) rather than a fixed route component.
func isDynamicSegment(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Pure numeric
	allDigits := true
	for _, c := range s {
		if c < '0' || c > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return true
	}
	// UUID: 8-4-4-4-12 hex with dashes (36 chars)
	if len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' {
		return true
	}
	// Long hex strings (>8 chars, all hex)
	if len(s) > 8 {
		allHex := true
		for _, c := range s {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				allHex = false
				break
			}
		}
		if allHex {
			return true
		}
	}
	return false
}

// indexBytesCI performs a case-insensitive search for needle in haystack.
// The needle must be lowercase. Returns the index of the first match or -1.
func indexBytesCI(haystack, needle []byte) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			hb := haystack[i+j]
			// Fast lowercase for ASCII letters
			if hb >= 'A' && hb <= 'Z' {
				hb += 'a' - 'A'
			}
			if hb != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
