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

func TestStitcherTraceparentServerNotDeferred(t *testing.T) {
	logger := zap.NewNop()

	t.Run("not_deferred_when_no_match", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)

		now := time.Now()
		// SERVER span with confirmed traceparent (traceID + parentSpanID from upstream
		// sk_msg injection). Should NOT be deferred — it already has correct linking.
		serverSpan := &Span{
			TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
			SpanID:       "dddd0000dddd0000",
			ParentSpanID: "cccc0000cccc0000", // from upstream sk_msg traceparent
			Kind:         SpanKindServer,
			StartTime:    now,
			Protocol:     "http",
			PID:          2000,
			Attributes: map[string]string{
				"olly.trace_source":   "traceparent",
				"http.request.method": "POST",
				"url.path":            "/mcp",
			},
			ServiceName: "mcp-server",
		}

		deferred := s.ProcessSpan(serverSpan)
		if deferred {
			t.Error("SERVER with confirmed traceparent should NOT be deferred")
		}
		if s.PendingCount() != 0 {
			t.Errorf("expected 0 pending for traceparent-confirmed SERVER, got %d", s.PendingCount())
		}
	})

	t.Run("matches_pending_client", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)

		var stitched *Span
		s.OnStitchedSpan(func(span *Span) {
			stitched = span
		})

		now := time.Now()
		// CLIENT deferred first (no injected marker — TID mismatch)
		clientSpan := &Span{
			TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
			SpanID:       "bbbb0000bbbb0000",
			ParentSpanID: "1111000011110000",
			Kind:         SpanKindClient,
			StartTime:    now,
			RemoteAddr:   "10.0.0.2",
			RemotePort:   3001,
			Protocol:     "http",
			PID:          1000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/catalog",
			},
			ServiceName: "order-service",
		}
		deferred := s.ProcessSpan(clientSpan)
		if !deferred {
			t.Fatal("expected CLIENT to be deferred")
		}

		// Traceparent-confirmed SERVER arrives and should match the pending CLIENT
		serverSpan := &Span{
			TraceID:      "dddd0000dddd0000dddd0000dddd0000", // BPF-generated traceID
			SpanID:       "eeee0000eeee0000",
			ParentSpanID: "ffff0000ffff0000", // from sk_msg traceparent
			Kind:         SpanKindServer,
			StartTime:    now.Add(2 * time.Millisecond),
			Protocol:     "http",
			PID:          2000,
			Attributes: map[string]string{
				"olly.trace_source":   "traceparent",
				"http.request.method": "GET",
				"url.path":            "/api/catalog",
			},
			ServiceName: "catalog-service",
		}
		deferred = s.ProcessSpan(serverSpan)
		if deferred {
			t.Error("traceparent SERVER should NOT be deferred even when matching")
		}

		// SERVER should be stitched: join CLIENT's trace, preserve traceparent parent
		if serverSpan.TraceID != "aaaa0000aaaa0000aaaa0000aaaa0000" {
			t.Errorf("SERVER should adopt CLIENT traceID, got %s", serverSpan.TraceID)
		}
		// Traceparent parent preserved (not overwritten by stitcher)
		if serverSpan.ParentSpanID != "ffff0000ffff0000" {
			t.Errorf("SERVER traceparent parent should be preserved, got %s", serverSpan.ParentSpanID)
		}
		if serverSpan.Attributes["olly.stitched"] != "true" {
			t.Error("expected olly.stitched=true on SERVER")
		}
		// TraceMerge should be created: old SERVER traceID → CLIENT traceID
		if merged, ok := s.TraceMerge("dddd0000dddd0000dddd0000dddd0000"); !ok || merged != "aaaa0000aaaa0000aaaa0000aaaa0000" {
			t.Errorf("expected TraceMerge dddd→aaaa, got %s (ok=%v)", merged, ok)
		}
		// CLIENT clone re-exported
		if stitched == nil {
			t.Fatal("expected stitched callback for CLIENT clone")
		}
	})

	t.Run("without_traceparent_still_deferred", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)

		now := time.Now()
		// SERVER without traceparent should still be deferred (existing behavior)
		serverNoTP := &Span{
			TraceID:   "bbbb0000bbbb0000bbbb0000bbbb0000",
			SpanID:    "eeee0000eeee0000",
			Kind:      SpanKindServer,
			StartTime: now,
			Protocol:  "http",
			PID:       3000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/orders",
			},
			ServiceName: "order-service",
		}
		deferred := s.ProcessSpan(serverNoTP)
		if !deferred {
			t.Error("SERVER without traceparent should be deferred for stitching")
		}
	})

	t.Run("traceparent_without_parent_still_deferred", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)

		now := time.Now()
		// SERVER with traceparent but NO parentSpanID should still be deferred
		serverTPNoParent := &Span{
			TraceID:   "cccc0000cccc0000cccc0000cccc0000",
			SpanID:    "ffff0000ffff0000",
			Kind:      SpanKindServer,
			StartTime: now,
			Protocol:  "http",
			PID:       4000,
			Attributes: map[string]string{
				"olly.trace_source":   "traceparent",
				"http.request.method": "GET",
				"url.path":            "/items",
			},
			ServiceName: "item-service",
		}
		deferred := s.ProcessSpan(serverTPNoParent)
		if !deferred {
			t.Error("SERVER with traceparent but no parentSpanID should be deferred")
		}
	})
}

func TestStitcherTraceparentServerMatchesButThreadCtxStitched(t *testing.T) {
	logger := zap.NewNop()

	// SERVER span with olly.trace_source=traceparent and ParentSpanID tries to
	// match pending CLIENTs but is NOT deferred if no match found. When a CLIENT
	// IS pending, the SERVER matches and stitching occurs. The traceparent parent
	// is preserved (not overwritten by the stitcher).
	t.Run("traceparent_server_matches_client_rootless", func(t *testing.T) {
		// CLIENT has no parent → CLIENT adopts SERVER's trace.
		// SERVER's traceparent parent is preserved.
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

		serverSpan := &Span{
			TraceID:      "dddd0000dddd0000dddd0000dddd0000",
			SpanID:       "eeee0000eeee0000",
			ParentSpanID: "cccc0000cccc0000", // from sk_msg injection
			Kind:         SpanKindServer,
			StartTime:    clientSpan.StartTime.Add(5 * time.Millisecond),
			Protocol:     "http",
			PID:          2000,
			Attributes:   map[string]string{"olly.trace_source": "traceparent", "http.request.method": "GET", "url.path": "/health"},
		}

		s.ProcessSpan(clientSpan)
		deferred := s.ProcessSpan(serverSpan)

		// SERVER with traceparent should NOT be deferred
		if deferred {
			t.Error("traceparent-confirmed SERVER should not be deferred")
		}
		// ParentSpanID should be preserved from traceparent (not overwritten)
		if serverSpan.ParentSpanID != "cccc0000cccc0000" {
			t.Errorf("expected SERVER parentSpanID preserved=cccc0000cccc0000, got %s", serverSpan.ParentSpanID)
		}
		// CLIENT (rootless) adopts SERVER's traceID
		if serverSpan.Attributes["olly.stitched"] != "true" {
			t.Error("expected SERVER to be stitched with pending CLIENT")
		}
	})

	// SERVER span with parent from thread context (no olly.trace_source) SHOULD still be stitchable.
	t.Run("thread_ctx_server_stitched", func(t *testing.T) {
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

		if serverSpan2.Attributes["olly.stitched"] != "true" {
			t.Error("should stitch spans whose parent came from thread context (no traceparent)")
		}
		if serverSpan2.ParentSpanID != "1111000011110000" {
			t.Errorf("expected SERVER2 parentSpanID=1111000011110000, got %s", serverSpan2.ParentSpanID)
		}
	})
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

func TestStitcherInjectedClientByProtocol(t *testing.T) {
	logger := zap.NewNop()

	t.Run("http_injected_skipped", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)
		now := time.Now()
		// HTTP CLIENT with trace_source=injected: TID matched → sk_msg
		// injected correct traceparent → downstream extracts it (within
		// 256-byte capture) → deterministic link → skip stitcher.
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
			t.Error("HTTP CLIENT with injected trace should NOT be deferred (link is deterministic)")
		}
		if s.PendingCount() != 0 {
			t.Errorf("expected 0 pending for HTTP injected CLIENT, got %d", s.PendingCount())
		}
	})

	t.Run("mcp_injected_deferred", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)
		now := time.Now()
		// MCP CLIENT with trace_source=injected: sk_msg injects but MCP
		// headers push traceparent beyond 256-byte capture → downstream
		// often fails to extract → stitcher must defer for matching.
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
			t.Error("MCP CLIENT with injected trace should be deferred (downstream may not extract)")
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
	// MCP CLIENT span from Flask (sk_msg injected, but MCP SERVER may not
	// extract traceparent due to 256-byte eBPF capture limit → needs stitching)
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

	// CLIENT deferred (injected, but downstream may not extract traceparent)
	deferred := s.ProcessSpan(clientSpan)
	if !deferred {
		t.Fatal("MCP CLIENT should be deferred for stitching")
	}

	// SERVER matches the pending CLIENT
	deferred = s.ProcessSpan(serverSpan)
	if deferred {
		t.Fatal("SERVER that matched should not be deferred")
	}

	// Verify cross-service stitching: CLIENT has parent, so SERVER joins CLIENT's trace
	if serverSpan.ParentSpanID != clientSpan.SpanID {
		t.Errorf("SERVER.ParentSpanID should be CLIENT.SpanID: got %q, want %q",
			serverSpan.ParentSpanID, clientSpan.SpanID)
	}
	// SERVER should adopt CLIENT's traceID (CLIENT has parent → SERVER joins CLIENT's trace)
	if serverSpan.TraceID != "aaaa0000aaaa0000aaaa0000aaaa0000" {
		t.Errorf("SERVER should adopt CLIENT's traceID: got %q, want %q",
			serverSpan.TraceID, "aaaa0000aaaa0000aaaa0000aaaa0000")
	}

	// CLIENT clone should be re-exported unchanged (keeps its original traceID + parent)
	if len(stitchedSpans) != 1 {
		t.Fatalf("expected 1 stitched span (CLIENT clone), got %d", len(stitchedSpans))
	}
	stitchedClient := stitchedSpans[0]
	if stitchedClient.TraceID != "aaaa0000aaaa0000aaaa0000aaaa0000" {
		t.Errorf("stitched CLIENT should keep original traceID: got %q, want %q",
			stitchedClient.TraceID, "aaaa0000aaaa0000aaaa0000aaaa0000")
	}

	// CLIENT's ParentSpanID should be preserved (it's part of the Flask trace)
	if stitchedClient.ParentSpanID != "cccc0000cccc0000" {
		t.Errorf("stitched CLIENT's ParentSpanID should be preserved: got %q, want %q",
			stitchedClient.ParentSpanID, "cccc0000cccc0000")
	}

	// Both should have stitched attribute
	if serverSpan.Attributes["olly.stitched"] != "true" {
		t.Error("SERVER should have olly.stitched=true")
	}
	if stitchedClient.Attributes["olly.stitched"] != "true" {
		t.Error("CLIENT should have olly.stitched=true")
	}
}

func TestStitcherParentedClientPreservesTrace(t *testing.T) {
	logger := zap.NewNop()

	t.Run("client_first_server_second", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)
		var stitched *Span
		s.OnStitchedSpan(func(span *Span) {
			stitched = span
		})

		now := time.Now()
		// CLIENT span that has a parent (part of Go order-service trace)
		clientSpan := &Span{
			TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
			SpanID:       "bbbb0000bbbb0000",
			ParentSpanID: "1111000011110000", // Go SERVER's spanID
			Kind:         SpanKindClient,
			StartTime:    now,
			RemoteAddr:   "127.0.0.1",
			RemotePort:   8081,
			Protocol:     "http",
			PID:          1000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/catalog/WDG-001",
			},
			ServiceName: "order-service",
		}

		// SERVER span from Java catalog-service (no traceparent — sk_msg failed)
		serverSpan := &Span{
			TraceID:   "cccc0000cccc0000cccc0000cccc0000",
			SpanID:    "dddd0000dddd0000",
			Kind:      SpanKindServer,
			StartTime: now.Add(2 * time.Millisecond),
			Protocol:  "http",
			PID:       2000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/catalog/WDG-001",
			},
			ServiceName: "catalog-service",
		}

		// CLIENT deferred (no "injected" marker due to TID mismatch)
		s.ProcessSpan(clientSpan)
		s.ProcessSpan(serverSpan)

		// SERVER should join CLIENT's trace (CLIENT has parent)
		if serverSpan.TraceID != "aaaa0000aaaa0000aaaa0000aaaa0000" {
			t.Errorf("SERVER should adopt CLIENT traceID, got %s", serverSpan.TraceID)
		}
		if serverSpan.ParentSpanID != "bbbb0000bbbb0000" {
			t.Errorf("SERVER parent should be CLIENT spanID, got %s", serverSpan.ParentSpanID)
		}

		// CLIENT clone should be re-exported with preserved parent
		if stitched == nil {
			t.Fatal("expected stitched callback")
		}
		if stitched.ParentSpanID != "1111000011110000" {
			t.Errorf("CLIENT parent should be preserved, got %s", stitched.ParentSpanID)
		}
		if stitched.TraceID != "aaaa0000aaaa0000aaaa0000aaaa0000" {
			t.Errorf("CLIENT traceID should be preserved, got %s", stitched.TraceID)
		}
	})

	t.Run("server_first_client_second", func(t *testing.T) {
		s := NewStitcher(500*time.Millisecond, logger)
		var stitched *Span
		s.OnStitchedSpan(func(span *Span) {
			stitched = span
		})

		now := time.Now()
		// SERVER arrives first (Java catalog-service, no traceparent)
		serverSpan := &Span{
			TraceID:   "cccc0000cccc0000cccc0000cccc0000",
			SpanID:    "dddd0000dddd0000",
			Kind:      SpanKindServer,
			StartTime: now.Add(2 * time.Millisecond),
			Protocol:  "http",
			PID:       2000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/catalog/WDG-001",
			},
			ServiceName: "catalog-service",
		}

		// CLIENT arrives second (has parent in Go trace)
		clientSpan := &Span{
			TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
			SpanID:       "bbbb0000bbbb0000",
			ParentSpanID: "1111000011110000",
			Kind:         SpanKindClient,
			StartTime:    now,
			RemoteAddr:   "127.0.0.1",
			RemotePort:   8081,
			Protocol:     "http",
			PID:          1000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/catalog/WDG-001",
			},
			ServiceName: "order-service",
		}

		s.ProcessSpan(serverSpan)
		s.ProcessSpan(clientSpan)

		// CLIENT should keep its traceID and parent (not adopt SERVER's traceID)
		if clientSpan.TraceID != "aaaa0000aaaa0000aaaa0000aaaa0000" {
			t.Errorf("CLIENT traceID should be preserved, got %s", clientSpan.TraceID)
		}
		if clientSpan.ParentSpanID != "1111000011110000" {
			t.Errorf("CLIENT parent should be preserved, got %s", clientSpan.ParentSpanID)
		}

		// SERVER clone (re-exported via callback) should adopt CLIENT's traceID
		if stitched == nil {
			t.Fatal("expected stitched callback")
		}
		if stitched.TraceID != "aaaa0000aaaa0000aaaa0000aaaa0000" {
			t.Errorf("SERVER clone should adopt CLIENT traceID, got %s", stitched.TraceID)
		}
		if stitched.ParentSpanID != "bbbb0000bbbb0000" {
			t.Errorf("SERVER clone parent should be CLIENT spanID, got %s", stitched.ParentSpanID)
		}
	})

	t.Run("rootless_client_adopts_server", func(t *testing.T) {
		// When CLIENT has NO parent, existing behavior: CLIENT adopts SERVER's traceID
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
			RemoteAddr: "127.0.0.1",
			RemotePort: 8081,
			Protocol:   "http",
			PID:        1000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/catalog/WDG-001",
			},
		}

		serverSpan := &Span{
			TraceID:   "cccc0000cccc0000cccc0000cccc0000",
			SpanID:    "dddd0000dddd0000",
			Kind:      SpanKindServer,
			StartTime: now.Add(2 * time.Millisecond),
			Protocol:  "http",
			PID:       2000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/catalog/WDG-001",
			},
		}

		s.ProcessSpan(clientSpan)
		s.ProcessSpan(serverSpan)

		// CLIENT has no parent → adopts SERVER's traceID (existing behavior)
		if stitched == nil {
			t.Fatal("expected stitched callback")
		}
		if stitched.TraceID != "cccc0000cccc0000cccc0000cccc0000" {
			t.Errorf("rootless CLIENT should adopt SERVER traceID, got %s", stitched.TraceID)
		}
		if serverSpan.ParentSpanID != "bbbb0000bbbb0000" {
			t.Errorf("SERVER parent should be CLIENT spanID, got %s", serverSpan.ParentSpanID)
		}
	})
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

func TestStitcherMCPMethodDisambiguates(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	var stitchedSpans []*Span
	s.OnStitchedSpan(func(span *Span) {
		stitchedSpans = append(stitchedSpans, span)
	})

	now := time.Now()
	// Two MCP CLIENT spans: same POST /mcp, different mcp.method.name
	clientToolsCall := &Span{
		TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:       "1111000011110000",
		ParentSpanID: "0000000000000001",
		Kind:         SpanKindClient,
		StartTime:    now,
		RemoteAddr:   "127.0.0.1",
		RemotePort:   8765,
		Protocol:     "mcp",
		PID:          1000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/mcp",
			"mcp.method.name":    "tools/call",
			"olly.trace_source":   "injected",
		},
		ServiceName: "app",
	}

	clientInitialize := &Span{
		TraceID:      "bbbb0000bbbb0000bbbb0000bbbb0000",
		SpanID:       "2222000022220000",
		ParentSpanID: "0000000000000002",
		Kind:         SpanKindClient,
		StartTime:    now.Add(1 * time.Millisecond),
		RemoteAddr:   "127.0.0.1",
		RemotePort:   8765,
		Protocol:     "mcp",
		PID:          1000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/mcp",
			"mcp.method.name":    "initialize",
			"olly.trace_source":   "injected",
		},
		ServiceName: "app",
	}

	s.ProcessSpan(clientToolsCall)
	s.ProcessSpan(clientInitialize)

	// SERVER span for tools/call — should match only clientToolsCall
	serverToolsCall := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "3333000033330000",
		Kind:      SpanKindServer,
		StartTime: now.Add(2 * time.Millisecond),
		Protocol:  "mcp",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/mcp",
			"mcp.method.name":    "tools/call",
		},
		ServiceName: "mcp-server",
	}

	s.ProcessSpan(serverToolsCall)

	// Should be stitched — mcp.method.name disambiguated to exactly 1 candidate
	if serverToolsCall.Attributes["olly.stitched"] != "true" {
		t.Error("expected MCP stitching when mcp.method.name disambiguates candidates")
	}
	if serverToolsCall.ParentSpanID != "1111000011110000" {
		t.Errorf("expected SERVER parent=clientToolsCall, got %s", serverToolsCall.ParentSpanID)
	}
	if serverToolsCall.TraceID != "aaaa0000aaaa0000aaaa0000aaaa0000" {
		t.Errorf("SERVER should adopt CLIENT traceID, got %s", serverToolsCall.TraceID)
	}

	// clientInitialize should still be pending (not consumed)
	if s.PendingCount() != 1 {
		t.Errorf("expected 1 pending (clientInitialize), got %d", s.PendingCount())
	}
}

func TestStitcherMCPWithoutMethodNameIsAmbiguous(t *testing.T) {
	// Without mcp.method.name, two MCP spans share POST /mcp → ambiguous
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	now := time.Now()
	client1 := &Span{
		TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:       "1111000011110000",
		ParentSpanID: "0000000000000001",
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
	client2 := &Span{
		TraceID:      "bbbb0000bbbb0000bbbb0000bbbb0000",
		SpanID:       "2222000022220000",
		ParentSpanID: "0000000000000002",
		Kind:         SpanKindClient,
		StartTime:    now.Add(1 * time.Millisecond),
		RemoteAddr:   "127.0.0.1",
		RemotePort:   8765,
		Protocol:     "mcp",
		PID:          1001,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/mcp",
			"olly.trace_source":   "injected",
		},
		ServiceName: "app-2",
	}

	s.ProcessSpan(client1)
	s.ProcessSpan(client2)

	// SERVER without mcp.method.name — both clients have empty path (mcp.method.name not set)
	// so path matching is skipped, producing 2 candidates → ambiguous
	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "3333000033330000",
		Kind:      SpanKindServer,
		StartTime: now.Add(2 * time.Millisecond),
		Protocol:  "mcp",
		PID:       2000,
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/mcp",
		},
		ServiceName: "mcp-server",
	}

	s.ProcessSpan(serverSpan)

	// Should NOT be stitched — ambiguous (empty path matches both)
	if serverSpan.Attributes["olly.stitched"] == "true" {
		t.Error("should not stitch MCP spans without mcp.method.name when ambiguous")
	}
}

func TestStitcherOverwritesParentRegardlessOfTraceSource(t *testing.T) {
	logger := zap.NewNop()

	t.Run("traceparent_server_matches_and_preserves_parent", func(t *testing.T) {
		// SERVER with olly.trace_source=traceparent + ParentSpanID tries to match
		// pending CLIENTs. When a CLIENT is pending, stitching happens but the
		// traceparent parent is preserved (not overwritten by stitcher).
		s := NewStitcher(500*time.Millisecond, logger)

		now := time.Now()
		clientSpan := &Span{
			TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
			SpanID:       "bbbb0000bbbb0000",
			ParentSpanID: "1111000011110000",
			Kind:         SpanKindClient,
			StartTime:    now,
			RemoteAddr:   "10.0.0.2",
			RemotePort:   3001,
			Protocol:     "http",
			PID:          1000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/items",
			},
			ServiceName: "order-service",
		}

		serverSpan := &Span{
			TraceID:      "dddd0000dddd0000dddd0000dddd0000",
			SpanID:       "eeee0000eeee0000",
			ParentSpanID: "ffff0000ffff0000", // from sk_msg traceparent injection
			Kind:         SpanKindServer,
			StartTime:    now.Add(2 * time.Millisecond),
			Protocol:     "http",
			PID:          2000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/items",
				"olly.trace_source":   "traceparent",
			},
			ServiceName: "catalog-service",
		}

		s.ProcessSpan(clientSpan)
		deferred := s.ProcessSpan(serverSpan)

		// SERVER not deferred (traceparent)
		if deferred {
			t.Error("traceparent SERVER should not be deferred")
		}
		// ParentSpanID preserved from traceparent (stitcher respects it)
		if serverSpan.ParentSpanID != "ffff0000ffff0000" {
			t.Errorf("SERVER parentSpanID should be preserved, got %s", serverSpan.ParentSpanID)
		}
		// TraceID updated to CLIENT's trace (stitching happened)
		if serverSpan.TraceID != "aaaa0000aaaa0000aaaa0000aaaa0000" {
			t.Errorf("SERVER traceID should match CLIENT, got %s", serverSpan.TraceID)
		}
		// TraceMerge created
		if merged, ok := s.TraceMerge("dddd0000dddd0000dddd0000dddd0000"); !ok || merged != "aaaa0000aaaa0000aaaa0000aaaa0000" {
			t.Errorf("expected TraceMerge dddd→aaaa, got %s (ok=%v)", merged, ok)
		}
	})

	t.Run("server_without_traceparent_also_overwritten", func(t *testing.T) {
		// Verify the normal case: SERVER WITHOUT traceparent also gets parent overwritten
		s := NewStitcher(500*time.Millisecond, logger)

		now := time.Now()
		clientSpan := &Span{
			TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
			SpanID:       "bbbb0000bbbb0000",
			ParentSpanID: "1111000011110000",
			Kind:         SpanKindClient,
			StartTime:    now,
			RemoteAddr:   "10.0.0.2",
			RemotePort:   3001,
			Protocol:     "http",
			PID:          1000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/items",
			},
			ServiceName: "order-service",
		}

		serverSpan := &Span{
			TraceID:      "dddd0000dddd0000dddd0000dddd0000",
			SpanID:       "eeee0000eeee0000",
			ParentSpanID: "ffff0000ffff0000", // from thread context, NOT traceparent
			Kind:         SpanKindServer,
			StartTime:    now.Add(2 * time.Millisecond),
			Protocol:     "http",
			PID:          2000,
			Attributes: map[string]string{
				"http.request.method": "GET",
				"url.path":            "/api/items",
				// No olly.trace_source — parent is from thread context
			},
			ServiceName: "catalog-service",
		}

		s.ProcessSpan(clientSpan)
		s.ProcessSpan(serverSpan)

		// SERVER without traceparent should have parent OVERWRITTEN
		if serverSpan.ParentSpanID != "bbbb0000bbbb0000" {
			t.Errorf("SERVER without traceparent should have parent overwritten to CLIENT spanID, got %s", serverSpan.ParentSpanID)
		}
	})
}

func TestTraceMergeTransitive(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	// Simulate 3-hop chain: T_order → T_catalog → T_pricing
	// Each hop's BPF generates a new traceID, but we want them all
	// to resolve to the canonical T_order.
	s.AddTraceMerge("t_catalog_bpf", "t_order_bpf")
	s.AddTraceMerge("t_pricing_bpf", "t_catalog_bpf")

	// Single-hop merge
	if got, ok := s.TraceMerge("t_catalog_bpf"); !ok || got != "t_order_bpf" {
		t.Errorf("single-hop merge: expected t_order_bpf, got %s (ok=%v)", got, ok)
	}

	// Transitive merge: t_pricing_bpf → t_catalog_bpf → t_order_bpf
	if got, ok := s.TraceMerge("t_pricing_bpf"); !ok || got != "t_order_bpf" {
		t.Errorf("transitive merge: expected t_order_bpf, got %s (ok=%v)", got, ok)
	}

	// Unknown traceID should return not-found
	if _, ok := s.TraceMerge("unknown"); ok {
		t.Error("expected no merge for unknown traceID")
	}

	// Canonical traceID should return not-found (no self-loop)
	if _, ok := s.TraceMerge("t_order_bpf"); ok {
		t.Error("expected no merge for canonical traceID")
	}
}

// TestStitcherResolvesStaleDeferredTraceID verifies that when a deferred CLIENT
// span has a stale traceID (due to sk_msg injecting a wrong trace context from a
// concurrent request), the stitcher resolves it via TraceMerge before stitching.
func TestStitcherResolvesStaleDeferredTraceID(t *testing.T) {
	logger := zap.NewNop()
	s := NewStitcher(500*time.Millisecond, logger)

	var stitchedSpans []*Span
	s.OnStitchedSpan(func(span *Span) {
		stitchedSpans = append(stitchedSpans, span)
	})

	// Scenario: catalog-service has stale traceID from sk_msg injection.
	// Order-service CLIENT and catalog SERVER should both end up in T_correct.

	// Step 1: catalog CLIENT deferred with stale traceID T_stale.
	// No injected marker: TID mismatch caused sk_msg to inject stale context.
	catalogClient := &Span{
		TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0001", // T_stale
		SpanID:       "cccc0000cccc0001",
		ParentSpanID: "cccc0000cccc0002", // catalog SERVER spanID
		Kind:         SpanKindClient,
		StartTime:    time.Now(),
		RemoteAddr:   "10.0.0.3",
		RemotePort:   8082,
		PID:          200, // catalog-service PID
		Protocol:     "http",
		Attributes: map[string]string{
			"http.request.method":      "GET",
			"url.path":                 "/api/pricing/GDG-001",
			"http.response.status_code": "200",
		},
	}
	deferred := s.ProcessSpan(catalogClient)
	if !deferred {
		t.Fatal("expected catalog CLIENT to be deferred")
	}

	// Step 2: catalog SERVER stitched with order CLIENT → creates TraceMerge T_stale → T_correct.
	// Simulate by adding the merge directly.
	s.AddTraceMerge("aaaa0000aaaa0000aaaa0000aaaa0001", "aaaa0000aaaa0000aaaa0000aaaa0000")

	// Step 3: pricing SERVER arrives → matches deferred catalog CLIENT.
	pricingServer := &Span{
		TraceID:   "bbbb0000bbbb0000bbbb0000bbbb0000",
		SpanID:    "dddd0000dddd0001",
		Kind:      SpanKindServer,
		StartTime: time.Now(),
		RemoteAddr: "10.0.0.2",
		RemotePort: 8082,
		PID:        300, // pricing-service PID
		Protocol:   "http",
		Attributes: map[string]string{
			"http.request.method":      "GET",
			"url.path":                 "/api/pricing/GDG-001",
			"http.response.status_code": "200",
		},
	}
	s.ProcessSpan(pricingServer)

	// Verify: both should be in T_correct (the canonical trace).
	tCorrect := "aaaa0000aaaa0000aaaa0000aaaa0000"

	// The pricing SERVER should have joined the catalog CLIENT's resolved trace.
	if pricingServer.TraceID != tCorrect {
		t.Errorf("pricing SERVER traceID: expected %s (canonical), got %s", tCorrect, pricingServer.TraceID)
	}

	// The re-exported catalog CLIENT clone should also have the resolved trace.
	if len(stitchedSpans) == 0 {
		t.Fatal("expected catalog CLIENT to be re-exported via OnStitchedSpan")
	}
	catalogClone := stitchedSpans[0]
	if catalogClone.TraceID != tCorrect {
		t.Errorf("catalog CLIENT clone traceID: expected %s (canonical), got %s", tCorrect, catalogClone.TraceID)
	}
}
