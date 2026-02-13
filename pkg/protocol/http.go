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
func ExtractTraceContext(request []byte) TraceContext {
	var ctx TraceContext

	// Look for traceparent header (case-insensitive)
	lower := bytes.ToLower(request)
	needle := []byte("traceparent: ")

	idx := bytes.Index(lower, needle)
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
	parts := strings.Split(value, "-")
	if len(parts) != 4 {
		return ctx
	}

	ctx.TraceID = parts[1]
	ctx.SpanID = parts[2]
	flags, _ := strconv.ParseInt(parts[3], 16, 64)
	ctx.Sampled = (flags & 0x01) != 0

	// R1.2: Look for tracestate header
	tsNeedle := []byte("tracestate: ")
	tsIdx := bytes.Index(lower, tsNeedle)
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
