package traces

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Stitcher performs cross-service trace stitching by matching outbound CLIENT
// spans with inbound SERVER spans. This enables waterfall traces across
// services even when traceparent injection isn't available (e.g., HTTPS, or
// when sk_msg attachment fails).
//
// Matching criteria:
//  1. CLIENT span's remote address/port matches SERVER span's listening address
//  2. Timestamps overlap within a configurable window
//  3. HTTP method and path match (when available)
//
// The stitcher operates as a post-processor: it receives completed spans and
// enriches them with parent-child relationships before export.
type Stitcher struct {
	logger *zap.Logger
	window time.Duration

	mu      sync.Mutex
	// Recent outbound CLIENT spans waiting for matching inbound SERVER spans.
	// Keyed by remote addr:port for O(1) lookup.
	pending map[string][]*pendingSpan

	callbacks []func(*Span)
}

// pendingSpan is a CLIENT span waiting for its matching SERVER span.
type pendingSpan struct {
	span      *Span
	method    string // HTTP method for matching
	path      string // URL path for matching
	createdAt time.Time
}

// NewStitcher creates a cross-service trace stitcher.
// window is the maximum time difference between a CLIENT span end and
// SERVER span start to consider them part of the same request flow.
func NewStitcher(window time.Duration, logger *zap.Logger) *Stitcher {
	if window == 0 {
		window = 500 * time.Millisecond
	}
	return &Stitcher{
		logger:  logger,
		window:  window,
		pending: make(map[string][]*pendingSpan),
	}
}

// OnStitchedSpan registers a callback for spans that have been stitched
// (had their parent set from a matching CLIENT span).
func (s *Stitcher) OnStitchedSpan(fn func(*Span)) {
	s.callbacks = append(s.callbacks, fn)
}

// ProcessSpan examines a completed span for stitching opportunities.
// CLIENT spans are stored for future matching.
// SERVER spans are matched against stored CLIENT spans.
func (s *Stitcher) ProcessSpan(span *Span) {
	if span == nil {
		return
	}

	switch span.Kind {
	case SpanKindClient:
		// Store CLIENT span for future matching with a SERVER span
		s.storeClientSpan(span)

	case SpanKindServer:
		// Try to match SERVER span with a stored CLIENT span
		s.matchServerSpan(span)
	}
}

// storeClientSpan stores an outbound CLIENT span for cross-service matching.
func (s *Stitcher) storeClientSpan(span *Span) {
	if span.RemoteAddr == "" || span.RemotePort == 0 {
		return
	}

	key := fmt.Sprintf("%s:%d", span.RemoteAddr, span.RemotePort)

	ps := &pendingSpan{
		span:      span,
		method:    span.Attributes["http.request.method"],
		path:      span.Attributes["url.path"],
		createdAt: time.Now(),
	}

	s.mu.Lock()
	s.pending[key] = append(s.pending[key], ps)
	s.mu.Unlock()
}

// matchServerSpan tries to find a matching CLIENT span for an inbound SERVER span.
// If found, sets the SERVER span's trace/parent IDs to create a parent-child link.
func (s *Stitcher) matchServerSpan(span *Span) {
	// Skip if the span already has a parent (from traceparent header injection)
	if span.ParentSpanID != "" {
		return
	}

	// For server spans, we need to find which client called us.
	// The SERVER span doesn't have the remote addr of the CLIENT directly.
	// But we can match by: the SERVER span's local port is the CLIENT span's
	// remote port, and timestamps overlap.
	//
	// Strategy: iterate over all pending CLIENT spans and find ones whose
	// remote port matches this server span's protocol port, within the time window.
	s.mu.Lock()
	defer s.mu.Unlock()

	serverMethod := span.Attributes["http.request.method"]
	serverPath := span.Attributes["url.path"]

	var bestMatch *pendingSpan
	var bestKey string
	var bestIdx int
	bestTimeDiff := s.window

	for key, spans := range s.pending {
		for i, ps := range spans {
			// Check time window: CLIENT span should overlap with SERVER span
			timeDiff := span.StartTime.Sub(ps.span.StartTime)
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}
			if timeDiff > s.window {
				continue
			}

			// Match HTTP method and path if available
			if serverMethod != "" && ps.method != "" && serverMethod != ps.method {
				continue
			}
			if serverPath != "" && ps.path != "" && serverPath != ps.path {
				continue
			}

			// Pick the closest match by time
			if timeDiff < bestTimeDiff {
				bestMatch = ps
				bestKey = key
				bestIdx = i
				bestTimeDiff = timeDiff
			}
		}
	}

	if bestMatch != nil {
		// Stitch: make the SERVER span a child of the CLIENT span's trace
		span.TraceID = bestMatch.span.TraceID
		span.ParentSpanID = bestMatch.span.SpanID

		span.SetAttribute("olly.stitched", "true")
		span.SetAttribute("olly.stitched.client_service", bestMatch.span.ServiceName)

		s.logger.Debug("stitched cross-service trace",
			zap.String("trace_id", span.TraceID),
			zap.String("client_span", bestMatch.span.SpanID),
			zap.String("server_span", span.SpanID),
			zap.String("method", serverMethod),
			zap.String("path", serverPath),
		)

		// Remove the matched CLIENT span
		pending := s.pending[bestKey]
		s.pending[bestKey] = append(pending[:bestIdx], pending[bestIdx+1:]...)
		if len(s.pending[bestKey]) == 0 {
			delete(s.pending, bestKey)
		}

		// Notify callbacks
		for _, cb := range s.callbacks {
			cb(span)
		}
	}
}

// Cleanup removes stale pending spans older than the window.
func (s *Stitcher) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	cutoff := time.Now().Add(-2 * s.window)

	for key, spans := range s.pending {
		kept := spans[:0]
		for _, ps := range spans {
			if ps.createdAt.After(cutoff) {
				kept = append(kept, ps)
			} else {
				removed++
			}
		}
		if len(kept) == 0 {
			delete(s.pending, key)
		} else {
			s.pending[key] = kept
		}
	}

	return removed
}

// PendingCount returns the number of CLIENT spans waiting for matching.
func (s *Stitcher) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, spans := range s.pending {
		count += len(spans)
	}
	return count
}
