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
		Attributes: map[string]string{
			"http.request.method": "GET",
			"url.path":            "/orders",
		},
		ServiceName: "service-b",
	}

	// Process CLIENT first, then SERVER
	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// CLIENT should adopt SERVER's traceID (preserving SERVER's intra-process children)
	if clientSpan.TraceID != serverSpan.TraceID {
		t.Errorf("expected CLIENT traceID=%s (SERVER's), got %s", serverSpan.TraceID, clientSpan.TraceID)
	}
	// SERVER should have CLIENT as parent
	if serverSpan.ParentSpanID != clientSpan.SpanID {
		t.Errorf("expected SERVER parentSpanID=%s, got %s", clientSpan.SpanID, serverSpan.ParentSpanID)
	}
	if serverSpan.Attributes["olly.stitched"] != "true" {
		t.Error("expected olly.stitched=true attribute on SERVER")
	}
	if serverSpan.Attributes["olly.stitched.client_service"] != "service-a" {
		t.Errorf("expected client_service=service-a, got %s", serverSpan.Attributes["olly.stitched.client_service"])
	}
	if stitched == nil {
		t.Error("expected stitched callback to be called")
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
		Attributes: map[string]string{},
	}

	// SERVER span already has a parent from traceparent header injection
	serverSpan := &Span{
		TraceID:      "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:       "dddd0000dddd0000",
		ParentSpanID: "bbbb0000bbbb0000",
		Kind:         SpanKindServer,
		StartTime:    clientSpan.StartTime.Add(5 * time.Millisecond),
		Attributes:   map[string]string{"olly.trace_source": "traceparent"},
	}

	s.ProcessSpan(clientSpan)
	s.ProcessSpan(serverSpan)

	// Should NOT stitch: parent came from actual traceparent header
	if serverSpan.Attributes["olly.stitched"] == "true" {
		t.Error("should not stitch spans that already have a traceparent parent")
	}

	// But a span with parent from thread context (no olly.trace_source) SHOULD be stitchable
	serverSpan2 := &Span{
		TraceID:      "cccc0000cccc0000cccc0000cccc0000",
		SpanID:       "eeee0000eeee0000",
		ParentSpanID: "ffff0000ffff0000",
		Kind:         SpanKindServer,
		StartTime:    clientSpan.StartTime.Add(5 * time.Millisecond),
		Attributes:   map[string]string{},
	}

	// Need a new client span since the first was consumed
	clientSpan2 := &Span{
		TraceID:     "aaaa0000aaaa0000aaaa0000aaaa0000",
		SpanID:      "1111000011110000",
		Kind:        SpanKindClient,
		StartTime:   time.Now(),
		RemoteAddr:  "10.0.0.2",
		RemotePort:  3001,
		Attributes:  map[string]string{},
		ServiceName: "service-a",
	}
	s.ProcessSpan(clientSpan2)
	s.ProcessSpan(serverSpan2)

	// Should be stitched: parent was from thread context, not traceparent
	if serverSpan2.Attributes["olly.stitched"] != "true" {
		t.Error("should stitch spans whose parent came from thread context (no traceparent)")
	}
	// CLIENT should adopt SERVER's traceID
	if clientSpan2.TraceID != serverSpan2.TraceID {
		t.Errorf("expected CLIENT2 traceID=%s (SERVER2's), got %s", serverSpan2.TraceID, clientSpan2.TraceID)
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
		Attributes: map[string]string{
			"http.request.method": "POST",
			"url.path":            "/orders",
		},
		ServiceName: "service-a",
	}

	s.ProcessSpan(serverSpan) // SERVER first
	s.ProcessSpan(clientSpan) // CLIENT second — should match stored SERVER

	// CLIENT should adopt SERVER's traceID
	if clientSpan.TraceID != serverSpan.TraceID {
		t.Errorf("expected CLIENT traceID=%s (SERVER's), got %s", serverSpan.TraceID, clientSpan.TraceID)
	}
	if serverSpan.ParentSpanID != clientSpan.SpanID {
		t.Errorf("expected SERVER parentSpanID=%s, got %s", clientSpan.SpanID, serverSpan.ParentSpanID)
	}
	if serverSpan.Attributes["olly.stitched"] != "true" {
		t.Error("expected olly.stitched=true on SERVER span")
	}
	if stitched == nil {
		t.Error("expected stitched callback to be called")
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
		Attributes: map[string]string{},
	}

	serverSpan := &Span{
		TraceID:   "cccc0000cccc0000cccc0000cccc0000",
		SpanID:    "dddd0000dddd0000",
		Kind:      SpanKindServer,
		StartTime: time.Now(),
		Attributes: map[string]string{},
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
		Attributes: map[string]string{},
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
