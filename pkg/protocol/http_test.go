// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"testing"
)

func TestHTTPDetect(t *testing.T) {
	p := &HTTPParser{}

	tests := []struct {
		name   string
		data   []byte
		port   uint16
		expect bool
	}{
		{"GET request", []byte("GET / HTTP/1.1\r\n"), 0, true},
		{"POST request", []byte("POST /api HTTP/1.1\r\n"), 0, true},
		{"HTTP response", []byte("HTTP/1.1 200 OK\r\n"), 0, true},
		{"Binary data", []byte{0x00, 0x01, 0x02, 0x03}, 0, false},
		{"Too short", []byte("GE"), 0, false},
		{"PUT request", []byte("PUT /resource HTTP/1.1\r\n"), 0, true},
		{"DELETE request", []byte("DELETE /item/1 HTTP/1.1\r\n"), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Detect(tt.data, tt.port)
			if got != tt.expect {
				t.Errorf("Detect(%q, %d) = %v, want %v", tt.data, tt.port, got, tt.expect)
			}
		})
	}
}

func TestHTTPParse(t *testing.T) {
	p := &HTTPParser{}

	request := []byte("GET /api/users?page=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")

	attrs, err := p.Parse(request, response)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if attrs.HTTPMethod != "GET" {
		t.Errorf("method = %q, want GET", attrs.HTTPMethod)
	}
	if attrs.HTTPPath != "/api/users" {
		t.Errorf("path = %q, want /api/users", attrs.HTTPPath)
	}
	if attrs.HTTPQuery != "page=1" {
		t.Errorf("query = %q, want page=1", attrs.HTTPQuery)
	}
	if attrs.HTTPStatusCode != 200 {
		t.Errorf("status = %d, want 200", attrs.HTTPStatusCode)
	}
	if attrs.HTTPHost != "example.com" {
		t.Errorf("host = %q, want example.com", attrs.HTTPHost)
	}
	if attrs.Error {
		t.Error("unexpected error flag")
	}
}

func TestHTTPParseError(t *testing.T) {
	p := &HTTPParser{}

	request := []byte("GET /fail HTTP/1.1\r\nHost: example.com\r\n\r\n")
	response := []byte("HTTP/1.1 500 Internal Server Error\r\n\r\n")

	attrs, err := p.Parse(request, response)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if attrs.HTTPStatusCode != 500 {
		t.Errorf("status = %d, want 500", attrs.HTTPStatusCode)
	}
	if !attrs.Error {
		t.Error("expected error flag for 500")
	}
}

func TestExtractTraceParent(t *testing.T) {
	request := []byte("GET / HTTP/1.1\r\ntraceparent: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01\r\n\r\n")

	traceID, spanID, sampled := ExtractTraceParent(request)

	if traceID != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("traceID = %q", traceID)
	}
	if spanID != "b7ad6b7169203331" {
		t.Errorf("spanID = %q", spanID)
	}
	if !sampled {
		t.Error("expected sampled=true")
	}
}

// TestExtractTraceContextCaseInsensitive verifies that the B12 fix (indexBytesCI
// instead of bytes.ToLower) correctly handles mixed-case, lowercase, and
// uppercase "Traceparent:" headers.
func TestExtractTraceContextCaseInsensitive(t *testing.T) {
	const wantTraceID = "0af7651916cd43dd8448eb211c80319c"
	const wantSpanID = "b7ad6b7169203331"
	traceparentValue := "00-" + wantTraceID + "-" + wantSpanID + "-01"

	tests := []struct {
		name       string
		headerName string
	}{
		{"lowercase", "traceparent"},
		{"uppercase", "TRACEPARENT"},
		{"mixed TitleCase", "Traceparent"},
		{"mixed alternating", "tRaCePaReNt"},
		{"mixed caps prefix", "TRACEparent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := []byte("GET / HTTP/1.1\r\n" + tt.headerName + ": " + traceparentValue + "\r\n\r\n")
			ctx := ExtractTraceContext(request)

			if ctx.TraceID != wantTraceID {
				t.Errorf("TraceID = %q, want %q", ctx.TraceID, wantTraceID)
			}
			if ctx.SpanID != wantSpanID {
				t.Errorf("SpanID = %q, want %q", ctx.SpanID, wantSpanID)
			}
			if !ctx.Sampled {
				t.Error("expected Sampled=true")
			}
		})
	}

	// Verify no match when header is absent
	t.Run("no header", func(t *testing.T) {
		request := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		ctx := ExtractTraceContext(request)
		if ctx.TraceID != "" {
			t.Errorf("TraceID = %q, want empty", ctx.TraceID)
		}
	})

	// Verify tracestate is also extracted case-insensitively
	t.Run("mixed case tracestate", func(t *testing.T) {
		request := []byte("GET / HTTP/1.1\r\nTRACEPARENT: " + traceparentValue + "\r\nTraceState: congo=t61rcWkgMzE\r\n\r\n")
		ctx := ExtractTraceContext(request)
		if ctx.TraceID != wantTraceID {
			t.Errorf("TraceID = %q, want %q", ctx.TraceID, wantTraceID)
		}
		if ctx.TraceState != "congo=t61rcWkgMzE" {
			t.Errorf("TraceState = %q, want %q", ctx.TraceState, "congo=t61rcWkgMzE")
		}
	})
}
