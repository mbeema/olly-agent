// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

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
// Matching is bidirectional: whichever span arrives first is stored, and when
// the counterpart arrives it's matched. This handles both orderings:
//   - CLIENT arrives first → stored, matched when SERVER arrives
//   - SERVER arrives first → stored, matched when CLIENT arrives
//
// Matching criteria:
//  1. Timestamps overlap within a configurable window
//  2. HTTP method and path match (when available)
//
// The stitcher operates as a post-processor: it receives completed spans and
// enriches them with parent-child relationships before export.
type Stitcher struct {
	logger *zap.Logger
	window time.Duration

	mu sync.Mutex
	// Pending CLIENT spans waiting for matching SERVER spans.
	pendingClients map[string][]*pendingSpan
	// Pending SERVER spans waiting for matching CLIENT spans.
	pendingServers map[string][]*pendingSpan

	callbacks []func(*Span)
}

// pendingSpan is a span waiting for its matching counterpart.
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
		logger:         logger,
		window:         window,
		pendingClients: make(map[string][]*pendingSpan),
		pendingServers: make(map[string][]*pendingSpan),
	}
}

// OnStitchedSpan registers a callback for spans that have been stitched
// (had their parent set from a matching CLIENT span).
func (s *Stitcher) OnStitchedSpan(fn func(*Span)) {
	s.callbacks = append(s.callbacks, fn)
}

// ProcessSpan examines a completed span for stitching opportunities.
// Both CLIENT and SERVER spans are checked against stored counterparts,
// and stored if no match is found.
func (s *Stitcher) ProcessSpan(span *Span) {
	if span == nil {
		return
	}

	switch span.Kind {
	case SpanKindClient:
		s.processClientSpan(span)
	case SpanKindServer:
		s.processServerSpan(span)
	}
}

// processClientSpan first tries to match against pending SERVER spans,
// then stores for future SERVER matching if no match found.
func (s *Stitcher) processClientSpan(span *Span) {
	if span.RemoteAddr == "" || span.RemotePort == 0 {
		return
	}

	method := span.Attributes["http.request.method"]
	path := span.Attributes["url.path"]

	s.mu.Lock()
	defer s.mu.Unlock()

	// Try to match against pending SERVER spans
	var bestMatch *pendingSpan
	var bestKey string
	var bestIdx int
	bestTimeDiff := s.window

	for key, spans := range s.pendingServers {
		for i, ps := range spans {
			timeDiff := span.StartTime.Sub(ps.span.StartTime)
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}
			if timeDiff > s.window {
				continue
			}
			if method != "" && ps.method != "" && method != ps.method {
				continue
			}
			if path != "" && ps.path != "" && path != ps.path {
				continue
			}
			if timeDiff < bestTimeDiff {
				bestMatch = ps
				bestKey = key
				bestIdx = i
				bestTimeDiff = timeDiff
			}
		}
	}

	if bestMatch != nil {
		// Stitch: CLIENT adopts SERVER's traceID (preserving the SERVER's
		// intra-process children which share that traceID), and SERVER
		// gets CLIENT as parent for the cross-service hierarchy.
		span.TraceID = bestMatch.span.TraceID
		bestMatch.span.ParentSpanID = span.SpanID

		span.SetAttribute("olly.stitched", "true")
		bestMatch.span.SetAttribute("olly.stitched", "true")
		bestMatch.span.SetAttribute("olly.stitched.client_service", span.ServiceName)

		s.logger.Debug("stitched cross-service trace (client→server)",
			zap.String("trace_id", span.TraceID),
			zap.String("client_span", span.SpanID),
			zap.String("server_span", bestMatch.span.SpanID),
			zap.String("method", method),
			zap.String("path", path),
		)

		// Remove matched SERVER span
		pending := s.pendingServers[bestKey]
		s.pendingServers[bestKey] = append(pending[:bestIdx], pending[bestIdx+1:]...)
		if len(s.pendingServers[bestKey]) == 0 {
			delete(s.pendingServers, bestKey)
		}

		for _, cb := range s.callbacks {
			cb(bestMatch.span)
		}
		return
	}

	// No SERVER match found — store CLIENT for future matching
	key := fmt.Sprintf("%s:%d", span.RemoteAddr, span.RemotePort)
	ps := &pendingSpan{
		span:      span,
		method:    method,
		path:      path,
		createdAt: time.Now(),
	}
	s.pendingClients[key] = append(s.pendingClients[key], ps)
}

// processServerSpan first tries to match against pending CLIENT spans,
// then stores for future CLIENT matching if no match found.
func (s *Stitcher) processServerSpan(span *Span) {
	// Skip if the span already has a parent from traceparent header injection.
	// Spans with parent from intra-process thread context (no olly.trace_source)
	// should still be stitchable to unify trace IDs with upstream CLIENT spans.
	if span.ParentSpanID != "" && span.Attributes["olly.trace_source"] == "traceparent" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	serverMethod := span.Attributes["http.request.method"]
	serverPath := span.Attributes["url.path"]

	// Try to match against pending CLIENT spans
	var bestMatch *pendingSpan
	var bestKey string
	var bestIdx int
	bestTimeDiff := s.window

	for key, spans := range s.pendingClients {
		for i, ps := range spans {
			timeDiff := span.StartTime.Sub(ps.span.StartTime)
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}
			if timeDiff > s.window {
				continue
			}
			if serverMethod != "" && ps.method != "" && serverMethod != ps.method {
				continue
			}
			if serverPath != "" && ps.path != "" && serverPath != ps.path {
				continue
			}
			if timeDiff < bestTimeDiff {
				bestMatch = ps
				bestKey = key
				bestIdx = i
				bestTimeDiff = timeDiff
			}
		}
	}

	if bestMatch != nil {
		// Stitch: CLIENT adopts SERVER's traceID (preserving the SERVER's
		// intra-process children which share that traceID), and SERVER
		// gets CLIENT as parent for the cross-service hierarchy.
		bestMatch.span.TraceID = span.TraceID
		span.ParentSpanID = bestMatch.span.SpanID

		bestMatch.span.SetAttribute("olly.stitched", "true")
		span.SetAttribute("olly.stitched", "true")
		span.SetAttribute("olly.stitched.client_service", bestMatch.span.ServiceName)

		s.logger.Debug("stitched cross-service trace (server←client)",
			zap.String("trace_id", span.TraceID),
			zap.String("client_span", bestMatch.span.SpanID),
			zap.String("server_span", span.SpanID),
			zap.String("method", serverMethod),
			zap.String("path", serverPath),
		)

		// Remove the matched CLIENT span
		pending := s.pendingClients[bestKey]
		s.pendingClients[bestKey] = append(pending[:bestIdx], pending[bestIdx+1:]...)
		if len(s.pendingClients[bestKey]) == 0 {
			delete(s.pendingClients, bestKey)
		}

		for _, cb := range s.callbacks {
			cb(span)
		}
		return
	}

	// No CLIENT match found — store SERVER for future matching
	key := fmt.Sprintf("server:%s:%s", serverMethod, serverPath)
	ps := &pendingSpan{
		span:      span,
		method:    serverMethod,
		path:      serverPath,
		createdAt: time.Now(),
	}
	s.pendingServers[key] = append(s.pendingServers[key], ps)
}

// Cleanup removes stale pending spans older than the window.
func (s *Stitcher) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	removed := 0
	cutoff := time.Now().Add(-2 * s.window)

	for key, spans := range s.pendingClients {
		kept := spans[:0]
		for _, ps := range spans {
			if ps.createdAt.After(cutoff) {
				kept = append(kept, ps)
			} else {
				removed++
			}
		}
		if len(kept) == 0 {
			delete(s.pendingClients, key)
		} else {
			s.pendingClients[key] = kept
		}
	}

	for key, spans := range s.pendingServers {
		kept := spans[:0]
		for _, ps := range spans {
			if ps.createdAt.After(cutoff) {
				kept = append(kept, ps)
			} else {
				removed++
			}
		}
		if len(kept) == 0 {
			delete(s.pendingServers, key)
		} else {
			s.pendingServers[key] = kept
		}
	}

	return removed
}

// PendingCount returns the number of spans waiting for matching.
func (s *Stitcher) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, spans := range s.pendingClients {
		count += len(spans)
	}
	for _, spans := range s.pendingServers {
		count += len(spans)
	}
	return count
}
