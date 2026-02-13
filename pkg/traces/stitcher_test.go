// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package traces

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestStitcherMatchesClientToServer(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	var stitched *Span
	s.OnStitchedSpan(func(span *Span) {
		stitched = span
	})

	// CLIENT span: service-A calls service-B at 10.0.0.2:3001
	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  time.Now(),
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
		ServiceName: "service-a",
	}

	// SERVER span: service-B receives the request (no traceparent upstream)
	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: clientSpan.StartTime.Add(5 * time.Millisecond),
		Protocol:  "http",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
		ServiceName: "service-b",
	}

	// Process CLIENT first (stored as clone), then SERVER (arrives, matches)
	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// SERVER (arriving span) should have CLIENT as parent and stitched attributes
	if serverSpan.ParentSpanID != "bbbb0000bbbb0000" {
		t.Errorf("expected SERVER parentSpanID=bbbb0000bbbb0000, got %s", serverSpan.ParentSpanID)
	}
	if serverSpan.Attributes["olly.stitched"] != "true" {
		t.Error("expected olly.stitched=true attribute on SERVER")
	}
	if serverSpan.Attributes["olly.stitched.client_service"] != "service-a" {
		t.Errorf("expected client_service=service-a, got %s", serverSpan.Attributes["olly.stitched.client_service"])
	}

	// H1 fix: The stitched callback receives the CLIENT clone with updated traceID
	if stitched == nil {
		t.Fatal("expected stitched callback to be called")
	}
	if stitched.TraceID != "cccc0000cccc0000cccc0000cccc0000" {
		t.Errorf("expected stitched CLIENT clone traceID=cccc0000cccc0000cccc0000cccc0000, got %s", stitched.TraceID)
	}
	if stitched.SpanID != "bbbb0000bbbb0000" {
		t.Errorf("expected stitched CLIENT clone spanID=bbbb0000bbbb0000, got %s", stitched.SpanID)
	}
}

func TestStitcherSkipsAlreadyParented(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  time.Now(),
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/health",
		},
	}

	// SERVER span already has a parent from traceparent header injection
	serverSpan := &Span{
		TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:       "dddd0000dddd0000",
		ParentSpanID: "bbbb0000bbbb0000",
		Kind:         SpanKindServer,
		StartTime:    clientSpan.StartTime.Add(5 * time.Millisecond),
		Protocol:     "http",
		PID:          2000,
		Attributes:   map[string]string{"olly.trace_source": "traceparent", "http.request.method": "GET", "url.path": "/health"},
	}

	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// Should NOT stitch: parent came from actual traceparent header
	if serverSpan.Attributes["olly.stitched"] == "true" {
		t.Error("should not stitch spans that already have a traceparent parent")
	}

	// But a span with parent from thread context (no olly.trace_source) SHOULD be stitchable.
	// Use a fresh stitcher to avoid ambiguity with the leftover pending CLIENT above.
	s2 := NewStitcher(500*time.Millisecond, logger)
	serverSpan2 := &Span{
		TraceID:      "cccc0000cccc0000cccc0000cccc0000",
		SpanID:       "eeee0000eeee0000",
		ParentSpanID: "ffff0000ffff0000",
		Kind:         SpanKindServer,
		StartTime:    time.Now().Add(5 * time.Millisecond),
		Protocol:     "http",
		PID:          2000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/health",
		},
	}

	clientSpan2 := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "1111000011110000",
		Kind:       SpanKindClient,
		StartTime:  time.Now(),
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/health",
		},
		ServiceName: "service-a",
	}
	s2.ProcessSpan(clientSpan2)
	s2.ProcessSpan(serverSpan2)

	// Should be stitched: parent was from thread context, not traceparent
	// SERVER (arriving span) gets stitched attributes
	if serverSpan2.Attributes["olly.stitched"] != "true" {
		t.Error("should stitch spans whose parent came from thread context (no traceparent)")
	}
	// SERVER (arriving) gets CLIENT's spanID as parent
	if serverSpan2.ParentSpanID != "1111000011110000" {
		t.Errorf("expected SERVER2 parentSpanID=1111000011110000, got %s", serverSpan2.ParentSpanID)
	}
}

func TestStitcherServerBeforeClient(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	var stitched *Span
	s.OnStitchedSpan(func(span *Span) {
		stitched = span
	})

	now := time.Now()
	// SERVER span arrives FIRST (common when Flask responds before curl pair completes)
	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(2 * time.Millisecond),
		Protocol:  "http",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/orders",
		},
		ServiceName: "service-b",
	}

	// CLIENT span arrives SECOND
	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/orders",
		},
		ServiceName: "service-a",
	}

	s.ProcessSpan(serverSpan) // SERVER first (stored as clone)
	s.ProcessSpan(clientSpan) // CLIENT second — should match stored SERVER clone

	// CLIENT (arriving span) should adopt SERVER's traceID
	if clientSpan.TraceID != "cccc0000cccc0000cccc0000cccc0000" {
		t.Errorf("expected CLIENT traceID=cccc0000cccc0000cccc0000cccc0000, got %s", clientSpan.TraceID)
	}
	if clientSpan.Attributes["olly.stitched"] != "true" {
		t.Error("expected olly.stitched=true on CLIENT span")
	}

	// H1 fix: The stitched callback receives the SERVER clone with updated parentSpanID
	if stitched == nil {
		t.Fatal("expected stitched callback to be called")
	}
	if stitched.ParentSpanID != clientSpan.SpanID {
		t.Errorf("expected stitched SERVER clone parentSpanID=%s, got %s", clientSpan.SpanID, stitched.ParentSpanID)
	}
	if stitched.Attributes["olly.stitched"] != "true" {
		t.Error("expected olly.stitched=true on stitched SERVER clone")
	}
}

func TestStitcherRejectsOutOfWindow(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(100*time.Millisecond, logger)

	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  time.Now().Add(-2 * time.Second),
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}

	serverSpan := &Span{
		TraceID:  "cccc0000cccc0000cccc0000cccc0000",
		SpanID:   "dddd0000dddd0000",
		Kind:     SpanKindServer,
		StartTime: time.Now(),
		Protocol: "http",
		PID:      2000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}

	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// Should NOT be stitched — too far apart
	if serverSpan.TraceID == clientSpan.TraceID {
		t.Error("should not stitch spans outside the time window")
	}
}

func TestStitcherMethodMismatch(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/orders",
		},
	}

	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(5 * time.Millisecond),
		Protocol:  "http",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}

	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// Should NOT match — method mismatch
	if serverSpan.TraceID == clientSpan.TraceID {
		t.Error("should not stitch spans with different HTTP methods")
	}
}

func TestStitcherCleanup(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(50*time.Millisecond, logger)

	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  time.Now(),
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}

	s.ProcessSpan(clientSpan)
	if s.PendingCount() != 1 {
		t.Fatalf("expected 1 pending span, got %d", s.PendingCount())
	}

	// Wait for span to become stale
	time.Sleep(150 * time.Millisecond)

	removed := s.Cleanup()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
	if s.PendingCount() != 0 {
		t.Errorf("expected 0 pending after cleanup, got %d", s.PendingCount())
	}
}

func TestStitcherNilSpan(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	// Should not panic
	s.ProcessSpan(nil)

	if s.PendingCount() != 0 {
		t.Errorf("expected 0 pending, got %d", s.PendingCount())
	}
}

func TestTraceParentFormat(t *testing.T) {
	span := &Span{
		TraceID: "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:  "bbbb0000bbbb0000",
	}
	expected := "00-aaaa0000aaaa0000aaaa0000aaaa0000-bbbb0000bbbb0000-01"
	got := span.TraceParent()
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestGenerateIDs(t *testing.T) {
	traceID := GenerateTraceID()
	if len(traceID) != 32 {
		t.Errorf("expected 32-char trace ID, got %d chars", len(traceID))
	}

	spanID := GenerateSpanID()
	if len(spanID) != 16 {
		t.Errorf("expected 16-char span ID, got %d chars", len(spanID))
	}

	// Verify uniqueness
	if GenerateTraceID() == traceID {
		t.Error("expected unique trace IDs")
	}
	if GenerateSpanID() == spanID {
		t.Error("expected unique span IDs")
	}
}

func TestStitcherSkipsSamePID(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	// Both spans from PID 1000 (same process — intra-process linking)
	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
		ServiceName: "service-a",
	}

	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(1 * time.Millisecond),
		Protocol:  "http",
		PID:       1000, // Same PID
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
		ServiceName: "service-a",
	}

	// CLIENT first, then SERVER
	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// Should NOT be stitched — same process
	if serverSpan.Attributes["olly.stitched"] == "true" {
		t.Error("should not stitch same-PID spans (client first)")
	}
	if serverSpan.ParentSpanID == clientSpan.SpanID {
		t.Error("SERVER should not get CLIENT as parent when same PID")
	}

	// Also test SERVER-first ordering
	s2 := NewStitcher(500*time.Millisecond, logger)
	serverSpan2 := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(1 * time.Millisecond),
		Protocol:  "http",
		PID:       1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}
	clientSpan2 := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000, // Same PID
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}

	s2.ProcessSpan(serverSpan2)
	s2.ProcessSpan(clientSpan2)

	// Should NOT be stitched — same process
	if clientSpan2.Attributes["olly.stitched"] == "true" {
		t.Error("should not stitch same-PID spans (server first)")
	}
}

func TestStitcherSkipsDBRedisMongoClientSpans(t *testing.T) {
	logger := zap.NewNop()

	for _, proto := range []string{"postgres", "mysql", "redis", "mongodb"} {
		t.Run(proto, func(t *testing.T) {
			s := NewStitcher(500*time.Millisecond, logger)

			clientSpan := &Span{
				TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
				SpanID:     "bbbb0000bbbb0000",
				Kind:       SpanKindClient,
				StartTime:  time.Now(),
				RemoteAddr: "10.0.0.2",
				RemotePort: 5432,
				Protocol:   proto,
				PID:        1000,
				Attributes: map[string]string{},
			}

			deferred := s.ProcessSpan(clientSpan)
			if deferred {
				t.Errorf("%s CLIENT span should not be deferred (stored) for stitching", proto)
			}
			if s.PendingCount() != 0 {
				t.Errorf("expected 0 pending for %s CLIENT, got %d", proto, s.PendingCount())
			}
		})
	}
}

func TestStitcherCrossServiceHTTPStillWorks(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	var stitched *Span
	s.OnStitchedSpan(func(span *Span) {
		stitched = span
	})

	now := time.Now()
	// Different PIDs = cross-service
	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "PUT",
			"url.path":            "/items/42",
		},
		ServiceName: "api-gateway",
	}

	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(3 * time.Millisecond),
		Protocol:  "http",
		PID:       2000, // Different PID
		Attributes: map[string]string{
			"http.request.method": "PUT",
			"url.path":            "/items/42",
		},
		ServiceName: "item-service",
	}

	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// Should be stitched — different PIDs, matching method/path
	if serverSpan.ParentSpanID != "bbbb0000bbbb0000" {
		t.Errorf("expected SERVER parentSpanID=bbbb0000bbbb0000, got %s", serverSpan.ParentSpanID)
	}
	if serverSpan.Attributes["olly.stitched"] != "true" {
		t.Error("expected olly.stitched=true on SERVER span")
	}
	if stitched == nil {
		t.Fatal("expected stitched callback for CLIENT clone")
	}
	if stitched.TraceID != "cccc0000cccc0000cccc0000cccc0000" {
		t.Errorf("expected stitched CLIENT clone traceID=cccc..., got %s", stitched.TraceID)
	}
}

func TestStitcherSkipsPIDZero(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	// CLIENT with PID=0 (unknown) should not be stored or matched
	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        0, // Unknown
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}

	deferred := s.ProcessSpan(clientSpan)
	if deferred {
		t.Error("CLIENT with PID=0 should not be deferred")
	}
	if s.PendingCount() != 0 {
		t.Errorf("expected 0 pending for PID=0 CLIENT, got %d", s.PendingCount())
	}

	// SERVER with PID=0 should not be stored or matched
	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(2 * time.Millisecond),
		Protocol:  "http",
		PID:       0, // Unknown
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}

	s.ProcessSpan(serverSpan)
	if s.PendingCount() != 0 {
		t.Errorf("expected 0 pending for PID=0 SERVER, got %d", s.PendingCount())
	}
}

func TestStitcherGRPCMatching(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	var stitched *Span
	s.OnStitchedSpan(func(span *Span) {
		stitched = span
	})

	now := time.Now()
	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 50051,
		Protocol:   "grpc",
		PID:        1000,
		Attributes: map[string]string{
			"rpc.method":  "GetUser",
			"rpc.service": "user.UserService",
			"rpc.system":  "grpc",
		},
	}

	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(3 * time.Millisecond),
		Protocol:  "grpc",
		PID:       2000,
		Attributes: map[string]string{
			"rpc.method":  "GetUser",
			"rpc.service": "user.UserService",
			"rpc.system":  "grpc",
		},
	}

	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// Should be stitched — matching rpc.method + rpc.service
	if serverSpan.Attributes["olly.stitched"] != "true" {
		t.Error("expected gRPC spans to be stitched via rpc.method/rpc.service")
	}
	if serverSpan.ParentSpanID != "bbbb0000bbbb0000" {
		t.Errorf("expected SERVER parentSpanID=bbbb0000bbbb0000, got %s", serverSpan.ParentSpanID)
	}
	if stitched == nil {
		t.Fatal("expected stitched callback")
	}
}

func TestStitcherGRPCMethodMismatch(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 50051,
		Protocol:   "grpc",
		PID:        1000,
		Attributes: map[string]string{
			"rpc.method":  "GetUser",
			"rpc.service": "user.UserService",
		},
	}

	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(3 * time.Millisecond),
		Protocol:  "grpc",
		PID:       2000,
		Attributes: map[string]string{
			"rpc.method":  "ListUsers",
			"rpc.service": "user.UserService",
		},
	}

	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// Should NOT match — different rpc.method
	if serverSpan.Attributes["olly.stitched"] == "true" {
		t.Error("should not stitch gRPC spans with different rpc.method")
	}
}

func TestStitcherSkipsServerWithNonHTTPProtocol(t *testing.T) {
	logger := zap.NewNop()

	for _, proto := range []string{"postgres", "mysql", "redis", "mongodb", "dns"} {
		t.Run(proto, func(t *testing.T) {
			s := NewStitcher(500*time.Millisecond, logger)

			serverSpan := &Span{
				TraceID:    "cccc0000cccc0000cccc0000cccc0000",
				SpanID:     "dddd0000dddd0000",
				Kind:       SpanKindServer,
				StartTime:  time.Now(),
				Protocol:   proto,
				PID:        2000,
				Attributes: map[string]string{},
			}

			s.ProcessSpan(serverSpan)
			if s.PendingCount() != 0 {
				t.Errorf("expected 0 pending for %s SERVER, got %d", proto, s.PendingCount())
			}
		})
	}
}

func TestStitcherRequiresMethodForMatching(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	// CLIENT with no method should not be stored
	clientSpan := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "bbbb0000bbbb0000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{}, // No method
	}

	deferred := s.ProcessSpan(clientSpan)
	if deferred {
		t.Error("CLIENT with no method should not be deferred")
	}
	if s.PendingCount() != 0 {
		t.Errorf("expected 0 pending for method-less CLIENT, got %d", s.PendingCount())
	}

	// SERVER with no method should not be stored
	serverSpan := &Span{
		TraceID:    "cccc0000cccc0000cccc0000cccc0000",
		SpanID:     "dddd0000dddd0000",
		Kind:       SpanKindServer,
		StartTime:  now.Add(2 * time.Millisecond),
		Protocol:   "http",
		PID:        2000,
		Attributes: map[string]string{}, // No method
	}

	s.ProcessSpan(serverSpan)
	if s.PendingCount() != 0 {
		t.Errorf("expected 0 pending for method-less SERVER, got %d", s.PendingCount())
	}
}

func TestStitcherAmbiguityGuard(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	// Two concurrent identical CLIENT spans from different PIDs
	// (e.g., service-A calls service-B with GET /orders twice)
	client1 := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "1111000011110000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
		ServiceName: "service-a",
	}
	client2 := &Span{
		TraceID:    "bbbb0000bbbb0000bbbb0000bbbb0000",
		SpanID:     "2222000022220000",
		Kind:       SpanKindClient,
		StartTime:  now.Add(1 * time.Millisecond),
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1001, // Different PID (another instance)
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
		ServiceName: "service-a-replica",
	}

	s.ProcessSpan(client1)
	s.ProcessSpan(client2)

	// SERVER arrives — matches both CLIENTs (same method, path, within window)
	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(3 * time.Millisecond),
		Protocol:  "http",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
		ServiceName: "service-b",
	}

	s.ProcessSpan(serverSpan)

	// Should NOT be stitched — ambiguous (2 candidates)
	if serverSpan.Attributes["olly.stitched"] == "true" {
		t.Error("should not stitch when multiple candidates match (ambiguity guard)")
	}

	// Both CLIENTs should still be pending (not consumed)
	if s.PendingCount() < 2 {
		t.Errorf("expected at least 2 pending (clients preserved), got %d", s.PendingCount())
	}
}

func TestStitcherQueryDisambiguates(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	var stitched *Span
	s.OnStitchedSpan(func(span *Span) {
		stitched = span
	})

	now := time.Now()
	// Two CLIENTs to same endpoint but with different query strings
	client1 := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "1111000011110000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
			"url.query":           "id=123",
		},
		ServiceName: "service-a",
	}
	client2 := &Span{
		TraceID:    "bbbb0000bbbb0000bbbb0000bbbb0000",
		SpanID:     "2222000022220000",
		Kind:       SpanKindClient,
		StartTime:  now.Add(1 * time.Millisecond),
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1001,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
			"url.query":           "id=456",
		},
		ServiceName: "service-a-replica",
	}

	s.ProcessSpan(client1)
	s.ProcessSpan(client2)

	// SERVER with query=id=123 — should match only client1
	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(3 * time.Millisecond),
		Protocol:  "http",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
			"url.query":           "id=123",
		},
		ServiceName: "service-b",
	}

	s.ProcessSpan(serverSpan)

	// Should be stitched — query disambiguated to exactly 1 candidate
	if serverSpan.Attributes["olly.stitched"] != "true" {
		t.Error("expected stitching when url.query disambiguates candidates")
	}
	if serverSpan.ParentSpanID != "1111000011110000" {
		t.Errorf("expected SERVER parent=client1, got %s", serverSpan.ParentSpanID)
	}
	if stitched == nil {
		t.Fatal("expected stitched callback for CLIENT clone")
	}
	if stitched.TraceID != "cccc0000cccc0000cccc0000cccc0000" {
		t.Errorf("expected client1 clone traceID=cccc..., got %s", stitched.TraceID)
	}
}

func TestStitcherStatusCodeDisambiguates(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	// Two CLIENTs: same method+path but different response status codes
	client200 := &Span{
		TraceID:    "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:     "1111000011110000",
		Kind:       SpanKindClient,
		StartTime:  now,
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method":       "GET",
			"url.path":                  "/orders",
			"http.response.status_code": "200",
		},
	}
	client404 := &Span{
		TraceID:    "bbbb0000bbbb0000bbbb0000bbbb0000",
		SpanID:     "2222000022220000",
		Kind:       SpanKindClient,
		StartTime:  now.Add(1 * time.Millisecond),
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1001,
		Attributes: map[string]string{
			"http.request.method":       "GET",
			"url.path":                  "/orders",
			"http.response.status_code": "404",
		},
	}

	s.ProcessSpan(client200)
	s.ProcessSpan(client404)

	// SERVER with 404 — should match only client404
	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(3 * time.Millisecond),
		Protocol:  "http",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method":       "GET",
			"url.path":                  "/orders",
			"http.response.status_code": "404",
		},
	}

	s.ProcessSpan(serverSpan)

	// Should be stitched to client404 (status code disambiguated)
	if serverSpan.Attributes["olly.stitched"] != "true" {
		t.Error("expected stitching when status code disambiguates candidates")
	}
	if serverSpan.ParentSpanID != "2222000022220000" {
		t.Errorf("expected SERVER parent=client404, got %s", serverSpan.ParentSpanID)
	}
}

func TestStitcherSkipsClientWithTraceparent(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	// CLIENT span that already has traceparent-based linking (sk_msg injection worked)
	clientSpan := &Span{
		TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:       "bbbb0000bbbb0000",
		ParentSpanID: "cccc0000cccc0000",
		Kind:         SpanKindClient,
		StartTime:    now,
		RemoteAddr:   "10.0.0.2",
		RemotePort:   3001,
		Protocol:     "http",
		PID:          1000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/api/orders",
			"olly.trace_source":   "traceparent",
		},
		ServiceName: "app",
	}

	deferred := s.ProcessSpan(clientSpan)
	if deferred {
		t.Error("CLIENT with traceparent should not be deferred (already linked)")
	}
	if s.PendingCount() != 0 {
		t.Errorf("expected 0 pending for traceparent CLIENT, got %d", s.PendingCount())
	}

	// Verify it didn't get stored — a SERVER arriving later should NOT match it
	serverSpan := &Span{
		TraceID:   "dddd0000dddd0000dddd0000dddd0000",
		SpanID:    "eeee0000eeee0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(5 * time.Millisecond),
		Protocol:  "http",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/api/orders",
		},
	}
	s.ProcessSpan(serverSpan)
	if serverSpan.Attributes["olly.stitched"] == "true" {
		t.Error("SERVER should not match a CLIENT that was skipped due to traceparent")
	}
}

func TestStitcherSkipsHTTPInjectedClientButDefersMCP(t *testing.T) {
	logger := zap.NewNop()

	t.Run("http_injected_skipped", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)
		now := time.Now()
		// HTTP CLIENT span with trace_source=injected: sk_msg injection is reliable
		// for HTTP (traceparent fits in 256-byte eBPF window), so the stitcher should
		// skip it — the downstream SERVER will extract the traceparent.
		clientSpan := &Span{
			TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
			SpanID:       "bbbb0000bbbb0000",
			ParentSpanID: "cccc0000cccc0000",
			Kind:         SpanKindClient,
			StartTime:    now,
			RemoteAddr:   "10.0.0.2",
			RemotePort:   3001,
			Protocol:     "http",
			PID:          1000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/orders",
				"olly.trace_source":   "injected",
			},
			ServiceName: "app",
		}
		deferred := s.ProcessSpan(clientSpan)
		if deferred {
			t.Error("HTTP CLIENT with injected spanID should NOT be deferred (injection is reliable for HTTP)")
		}
		if s.PendingCount() != 0 {
			t.Errorf("expected 0 pending for HTTP injected CLIENT, got %d", s.PendingCount())
		}
	})

	t.Run("mcp_injected_deferred", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)
		now := time.Now()
		// MCP CLIENT span with trace_source=injected: Python's requests library adds
		// many headers (~200 bytes), pushing the traceparent beyond the 256-byte eBPF
		// capture window. The receiver often fails to extract it. The stitcher should
		// defer MCP injected CLIENT spans for matching against SERVER spans.
		clientSpan := &Span{
			TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
			SpanID:       "bbbb0000bbbb0000",
			ParentSpanID: "cccc0000cccc0000",
			Kind:         SpanKindClient,
			StartTime:    now,
			RemoteAddr:   "10.0.0.3",
			RemotePort:   3003,
			Protocol:     "mcp",
			PID:          1000,
			Attributes: map[string]string{
				"http.request.method": "POST",
				"url.path":            "/mcp",
				"olly.trace_source":   "injected",
			},
			ServiceName: "app",
		}
		deferred := s.ProcessSpan(clientSpan)
		if !deferred {
			t.Error("MCP CLIENT with injected spanID should be deferred (injection unreliable for MCP)")
		}
		if s.PendingCount() != 1 {
			t.Errorf("expected 1 pending for MCP injected CLIENT, got %d", s.PendingCount())
		}
	})
}

func TestStitcherMCPClientServerMatching(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	var stitchedSpans []*Span
	s.OnStitchedSpan(func(span *Span) {
		stitchedSpans = append(stitchedSpans, span)
	})

	now := time.Now()
	// MCP CLIENT span from Flask (has injected trace_source + parent from Flask SERVER)
	clientSpan := &Span{
		TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:       "bbbb0000bbbb0000",
		ParentSpanID: "cccc0000cccc0000", // Flask SERVER's spanID
		Kind:         SpanKindClient,
		StartTime:    now,
		RemoteAddr:   "127.0.0.1",
		RemotePort:   8765,
		Protocol:     "mcp",
		PID:          1000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/mcp",
			"olly.trace_source":   "injected",
		},
		ServiceName: "app",
	}

	// MCP SERVER span from mcp-server (no traceparent extracted — beyond 256-byte limit)
	serverSpan := &Span{
		TraceID:   "dddd0000dddd0000dddd0000dddd0000",
		SpanID:    "eeee0000eeee0000",
		Kind:      SpanKindServer,
		StartTime: now.Add(1 * time.Millisecond),
		RemoteAddr: "127.0.0.1",
		RemotePort: 8765,
		Protocol:   "mcp",
		PID:        2000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/mcp",
		},
		ServiceName: "mcp-server",
	}

	// CLIENT deferred (injected, but stitcher processes it now)
	deferred := s.ProcessSpan(clientSpan)
	if !deferred {
		t.Fatal("MCP CLIENT should be deferred for stitching")
	}

	// SERVER matches the pending CLIENT
	deferred = s.ProcessSpan(serverSpan)
	if deferred {
		t.Fatal("SERVER spans should never be deferred")
	}

	// Verify cross-service stitching
	if serverSpan.ParentSpanID != clientSpan.SpanID {
		t.Errorf("SERVER.ParentSpanID should be CLIENT.SpanID: got %q, want %q",
			serverSpan.ParentSpanID, clientSpan.SpanID)
	}

	// CLIENT should adopt SERVER's traceID
	if len(stitchedSpans) != 1 {
		t.Fatalf("expected 1 stitched span (CLIENT clone), got %d", len(stitchedSpans))
	}
	stitchedClient := stitchedSpans[0]
	if stitchedClient.TraceID != serverSpan.TraceID {
		t.Errorf("stitched CLIENT should adopt SERVER's traceID: got %q, want %q",
			stitchedClient.TraceID, serverSpan.TraceID)
	}

	// CLIENT's ParentSpanID should be cleared (parent is in a different trace now)
	if stitchedClient.ParentSpanID != "" {
		t.Errorf("stitched CLIENT's ParentSpanID should be cleared (cross-trace ref): got %q",
			stitchedClient.ParentSpanID)
	}

	// Both should have stitched attribute
	if serverSpan.Attributes["olly.stitched"] != "true" {
		t.Error("SERVER should have olly.stitched=true")
	}
	if stitchedClient.Attributes["olly.stitched"] != "true" {
		t.Error("CLIENT should have olly.stitched=true")
	}
}

func TestStitcherAmbiguityGuardClientSide(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	// Two SERVER spans from different processes, same method+path
	server1 := &Span{
		TraceID:   "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:    "1111000011110000",
		Kind:      SpanKindServer,
		StartTime: now,
		Protocol:  "http",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}
	server2 := &Span{
		TraceID:   "bbbb0000bbbb0000bbbb0000bbbb0000",
		SpanID:    "2222000022220000",
		Kind:      SpanKindServer,
		StartTime: now.Add(1 * time.Millisecond),
		Protocol:  "http",
		PID:       2001,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}

	s.ProcessSpan(server1)
	s.ProcessSpan(server2)

	// CLIENT arrives — matches both SERVERs
	clientSpan := &Span{
		TraceID:    "cccc0000cccc0000cccc0000cccc0000",
		SpanID:     "dddd0000dddd0000",
		Kind:       SpanKindClient,
		StartTime:  now.Add(2 * time.Millisecond),
		RemoteAddr: "10.0.0.2",
		RemotePort: 3001,
		Protocol:   "http",
		PID:        1000,
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
	}

	s.ProcessSpan(clientSpan)

	// Should NOT be stitched — ambiguous
	if clientSpan.Attributes["olly.stitched"] == "true" {
		t.Error("should not stitch when multiple SERVER candidates match (ambiguity guard)")
	}
}
