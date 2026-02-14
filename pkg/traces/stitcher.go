// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
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

	// traceMerge records traceID replacements from stitching.
	// When a SERVER's traceID is changed to match a CLIENT's trace,
	// this map propagates the change to future spans from the same
	// downstream process (e.g., Java CLIENT → .NET spans get the
	// correct traceID if they arrive after the stitch).
	traceMerge sync.Map // old traceID → new traceID
}

// pendingSpan is a span waiting for its matching counterpart.
type pendingSpan struct {
	span       *Span
	method     string // HTTP method (or gRPC rpc.method) for matching
	path       string // URL path (or gRPC rpc.service) for matching
	query      string // URL query string for disambiguation at scale
	statusCode string // HTTP response status code for disambiguation
	pid        uint32 // Process ID for same-process filtering
	createdAt  time.Time
}

// maxPendingSpans caps the total number of pending spans to prevent unbounded
// memory growth under sustained load with no matching counterparts.
const maxPendingSpans = 10000

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
// C4 fix: protected by s.mu for thread safety.
func (s *Stitcher) OnStitchedSpan(fn func(*Span)) {
	s.mu.Lock()
	s.callbacks = append(s.callbacks, fn)
	s.mu.Unlock()
}

// TraceMerge looks up whether a traceID has been replaced by stitching.
// Returns the new traceID and true if a merge exists.
func (s *Stitcher) TraceMerge(traceID string) (string, bool) {
	if val, ok := s.traceMerge.Load(traceID); ok {
		return val.(string), true
	}
	return "", false
}

// ProcessSpan examines a completed span for stitching opportunities.
// Both CLIENT and SERVER spans are checked against stored counterparts,
// and stored if no match is found.
// Returns true if the span was deferred (stored for future matching).
// Deferred spans should NOT be exported by the caller — the stitcher
// will re-export them via the OnStitchedSpan callback when matched,
// or via Cleanup when they expire unmatched.
func (s *Stitcher) ProcessSpan(span *Span) bool {
	if span == nil {
		return false
	}

	switch span.Kind {
	case SpanKindClient:
		return s.processClientSpan(span)
	case SpanKindServer:
		return s.processServerSpan(span)
	}
	return false
}

// processClientSpan first tries to match against pending SERVER spans,
// then stores for future SERVER matching if no match found.
// Returns true if the span was stored (deferred) for future matching.
func (s *Stitcher) processClientSpan(span *Span) bool {
	// Skip already-stitched spans — re-exported clones from the stitch callback
	// re-enter via spanCh and must not be processed again.
	if span.Attributes["olly.stitched"] == "true" {
		return false
	}

	// Only stitch HTTP/gRPC/MCP CLIENT spans. DB/Redis/MongoDB/GenAI CLIENT
	// spans connect to unmonitored services — no matching SERVER span will
	// arrive. GenAI CLIENT spans go to external APIs (OpenAI, Anthropic, etc.)
	// which are not monitored by this agent. MCP CLIENT spans connect to
	// local MCP servers which ARE monitored.
	if span.Protocol != "http" && span.Protocol != "grpc" && span.Protocol != "mcp" {
		return false
	}

	// Skip if the span already has confirmed cross-service linking via traceparent.
	// "traceparent" means the span extracted a traceparent header from the request data,
	// confirming both sender and receiver have the same trace context.
	traceSource := span.Attributes["olly.trace_source"]
	if span.ParentSpanID != "" && traceSource == "traceparent" {
		return false
	}
	// For HTTP/gRPC, sk_msg injection is reliable: the traceparent header fits within
	// the 256-byte eBPF capture window, so the receiver will extract it. Skip these.
	// For MCP, Python's requests library adds many headers (~200 bytes), pushing the
	// traceparent beyond 256 bytes. The receiver often fails to extract it, so MCP
	// "injected" CLIENT spans must go through the stitcher for cross-service linking.
	if span.ParentSpanID != "" && traceSource == "injected" && span.Protocol != "mcp" {
		return false
	}

	// PID=0 means unknown process — can't determine cross-process vs same-process.
	if span.PID == 0 {
		return false
	}

	if span.RemoteAddr == "" || span.RemotePort == 0 {
		return false
	}

	mk := extractMatchKey(span)

	// Require at least a method for matching — without it, matching
	// degrades to timestamp-only which has high false-positive risk.
	if mk.method == "" {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Try to match against pending SERVER spans.
	// Track match count to detect ambiguity at high volume.
	var bestMatch *pendingSpan
	var bestKey string
	var bestIdx int
	bestTimeDiff := s.window
	matchCount := 0

	for key, spans := range s.pendingServers {
		for i, ps := range spans {
			// Skip same-process spans — intra-process linking is
			// handled by thread context in enrichPairContext.
			if ps.pid == span.PID {
				continue
			}
			timeDiff := span.StartTime.Sub(ps.span.StartTime)
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}
			if timeDiff > s.window {
				continue
			}
			// Method must match (both guaranteed non-empty by guards).
			if mk.method != ps.method {
				continue
			}
			if mk.path != "" && ps.path != "" && mk.path != ps.path {
				continue
			}
			// Query string disambiguation: /orders?id=123 vs /orders?id=456
			if mk.query != "" && ps.query != "" && mk.query != ps.query {
				continue
			}
			// Response status code: 200 vs 404 for same endpoint
			if mk.statusCode != "" && ps.statusCode != "" && mk.statusCode != ps.statusCode {
				continue
			}
			matchCount++
			if timeDiff < bestTimeDiff {
				bestMatch = ps
				bestKey = key
				bestIdx = i
				bestTimeDiff = timeDiff
			}
		}
	}

	if bestMatch != nil {
		// Ambiguity guard: if multiple candidates passed all filters,
		// don't stitch — we can't confidently pick the right one.
		// At millions of TPS, false negatives (unlinked traces) are
		// acceptable; false positives (wrong trace links) are not.
		// traceparent injection handles these cases deterministically.
		if matchCount > 1 {
			s.logger.Debug("skipping ambiguous stitch (client→server)",
				zap.Int("candidates", matchCount),
				zap.String("method", mk.method),
				zap.String("path", mk.path),
			)
			// Still store for future single-candidate matching.
			goto store
		}

		// Stitch direction depends on whether the CLIENT already has a parent.
		// When CLIENT has a ParentSpanID, it's part of an existing trace
		// hierarchy — SERVER should join CLIENT's trace to preserve the chain.
		// When CLIENT has no parent, it adopts SERVER's traceID to preserve
		// SERVER's intra-process children which share that traceID.
		if span.ParentSpanID != "" {
			// CLIENT has parent → SERVER joins CLIENT's trace
			oldTraceID := bestMatch.span.TraceID
			bestMatch.span.TraceID = span.TraceID
			bestMatch.span.ParentSpanID = span.SpanID
			if oldTraceID != span.TraceID {
				s.traceMerge.Store(oldTraceID, span.TraceID)
			}
		} else {
			// CLIENT has no parent → adopt SERVER's traceID
			if span.TraceID != bestMatch.span.TraceID {
				span.ParentSpanID = ""
			}
			span.TraceID = bestMatch.span.TraceID
			bestMatch.span.ParentSpanID = span.SpanID
		}

		span.SetAttribute("olly.stitched", "true")
		bestMatch.span.SetAttribute("olly.stitched", "true")
		bestMatch.span.SetAttribute("olly.stitched.client_service", span.ServiceName)

		s.logger.Debug("stitched cross-service trace (client→server)",
			zap.String("trace_id", span.TraceID),
			zap.String("client_span", span.SpanID),
			zap.String("server_span", bestMatch.span.SpanID),
			zap.String("method", mk.method),
			zap.String("path", mk.path),
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
		return false // matched in-place, caller should export
	}

store:
	// No unambiguous match — store a clone for future matching (with cap).
	// H1 fix: clone prevents mutation of the original span in the export pipeline.
	// Return true to tell caller NOT to export — the stitcher owns this span now.
	// It will be re-exported via OnStitchedSpan callback when matched, or
	// via Cleanup when it expires unmatched.
	if s.pendingCount() < maxPendingSpans {
		key := fmt.Sprintf("%s:%d", span.RemoteAddr, span.RemotePort)
		ps := &pendingSpan{
			span:       cloneSpan(span),
			method:     mk.method,
			path:       mk.path,
			query:      mk.query,
			statusCode: mk.statusCode,
			pid:        span.PID,
			createdAt:  time.Now(),
		}
		s.pendingClients[key] = append(s.pendingClients[key], ps)
		return true // deferred — do NOT export
	}
	return false
}

// processServerSpan first tries to match against pending CLIENT spans,
// then stores for future CLIENT matching if no match found.
func (s *Stitcher) processServerSpan(span *Span) bool {
	// Skip already-stitched spans — re-exported clones from the stitch callback
	// re-enter via spanCh and must not be processed again.
	if span.Attributes["olly.stitched"] == "true" {
		return false
	}

	// Only stitch HTTP/gRPC/MCP SERVER spans (symmetric with client filter).
	// GenAI spans are CLIENT-only (to external LLM APIs), so no SERVER filter needed.
	if span.Protocol != "http" && span.Protocol != "grpc" && span.Protocol != "mcp" {
		return false
	}

	// PID=0 means unknown process — can't determine cross-process vs same-process.
	if span.PID == 0 {
		return false
	}

	// SERVER spans with traceparent parents still go through stitching.
	// The traceparent may have been auto-injected by the upstream application
	// framework (.NET Activity, Spring context) rather than by sk_msg, creating
	// orphan parentSpanIDs that reference internal framework spans. Stitching
	// overwrites these with the correct CLIENT→SERVER link. For sk_msg-injected
	// traceparent, stitching produces the same correct result.

	s.mu.Lock()
	defer s.mu.Unlock()

	mk := extractMatchKey(span)

	// Require at least a method for matching — without it, matching
	// degrades to timestamp-only which has high false-positive risk.
	if mk.method == "" {
		return false
	}

	// Try to match against pending CLIENT spans.
	// Track match count to detect ambiguity at high volume.
	var bestMatch *pendingSpan
	var bestKey string
	var bestIdx int
	bestTimeDiff := s.window
	matchCount := 0

	for key, spans := range s.pendingClients {
		for i, ps := range spans {
			// Skip same-process spans — intra-process linking is
			// handled by thread context in enrichPairContext.
			if ps.pid == span.PID {
				continue
			}
			timeDiff := span.StartTime.Sub(ps.span.StartTime)
			if timeDiff < 0 {
				timeDiff = -timeDiff
			}
			if timeDiff > s.window {
				continue
			}
			// Method must match (both guaranteed non-empty by guards).
			if mk.method != ps.method {
				continue
			}
			if mk.path != "" && ps.path != "" && mk.path != ps.path {
				continue
			}
			// Query string disambiguation: /orders?id=123 vs /orders?id=456
			if mk.query != "" && ps.query != "" && mk.query != ps.query {
				continue
			}
			// Response status code: 200 vs 404 for same endpoint
			if mk.statusCode != "" && ps.statusCode != "" && mk.statusCode != ps.statusCode {
				continue
			}
			matchCount++
			if timeDiff < bestTimeDiff {
				bestMatch = ps
				bestKey = key
				bestIdx = i
				bestTimeDiff = timeDiff
			}
		}
	}

	if bestMatch != nil {
		// Ambiguity guard: if multiple candidates passed all filters,
		// don't stitch — we can't confidently pick the right one.
		if matchCount > 1 {
			s.logger.Debug("skipping ambiguous stitch (server←client)",
				zap.Int("candidates", matchCount),
				zap.String("method", mk.method),
				zap.String("path", mk.path),
			)
			// Store SERVER for future single-candidate matching.
			goto storeServer
		}

		// Stitch direction depends on whether the CLIENT already has a parent.
		// H1 fix: bestMatch.span is already a clone (safe to mutate).
		if bestMatch.span.ParentSpanID != "" {
			// CLIENT has parent → SERVER joins CLIENT's trace
			oldTraceID := span.TraceID
			span.TraceID = bestMatch.span.TraceID
			span.ParentSpanID = bestMatch.span.SpanID
			if oldTraceID != bestMatch.span.TraceID {
				s.traceMerge.Store(oldTraceID, bestMatch.span.TraceID)
			}
		} else {
			// CLIENT has no parent → CLIENT joins SERVER's trace
			if bestMatch.span.TraceID != span.TraceID {
				bestMatch.span.ParentSpanID = ""
			}
			bestMatch.span.TraceID = span.TraceID
			span.ParentSpanID = bestMatch.span.SpanID
		}

		bestMatch.span.SetAttribute("olly.stitched", "true")
		span.SetAttribute("olly.stitched", "true")
		span.SetAttribute("olly.stitched.client_service", bestMatch.span.ServiceName)

		s.logger.Debug("stitched cross-service trace (server←client)",
			zap.String("trace_id", span.TraceID),
			zap.String("client_span", bestMatch.span.SpanID),
			zap.String("server_span", span.SpanID),
			zap.String("method", mk.method),
			zap.String("path", mk.path),
		)

		// Remove the matched CLIENT span
		pending := s.pendingClients[bestKey]
		s.pendingClients[bestKey] = append(pending[:bestIdx], pending[bestIdx+1:]...)
		if len(s.pendingClients[bestKey]) == 0 {
			delete(s.pendingClients, bestKey)
		}

		// Re-export the CLIENT clone (unchanged if it had parent, updated if root)
		for _, cb := range s.callbacks {
			cb(bestMatch.span)
		}
		return false // matched in-place, caller should export
	}

storeServer:
	// No unambiguous match — store a clone for future matching (with cap).
	// H1 fix: clone prevents mutation of the original span in the export pipeline.
	// SERVER spans are NOT deferred — they're exported immediately because
	// they carry intra-process children (DB queries, outbound calls) that
	// share the same traceID. Deferring would delay the entire trace subtree.
	if s.pendingCount() < maxPendingSpans {
		key := fmt.Sprintf("server:%s:%s", mk.method, mk.path)
		ps := &pendingSpan{
			span:       cloneSpan(span),
			method:     mk.method,
			path:       mk.path,
			query:      mk.query,
			statusCode: mk.statusCode,
			pid:        span.PID,
			createdAt:  time.Now(),
		}
		s.pendingServers[key] = append(s.pendingServers[key], ps)
	}
	return false // SERVER is never deferred
}

// matchKey holds all fields used for span matching.
type matchKey struct {
	method     string
	path       string
	query      string
	statusCode string
}

// extractMatchKey returns matching fields from a span's attributes.
// For HTTP: uses method, path, query string, and response status code.
// For gRPC: uses rpc.method and rpc.service.
func extractMatchKey(span *Span) matchKey {
	if span.Protocol == "grpc" {
		return matchKey{
			method: span.Attributes["rpc.method"],
			path:   span.Attributes["rpc.service"],
		}
	}
	return matchKey{
		method:     span.Attributes["http.request.method"],
		path:       span.Attributes["url.path"],
		query:      span.Attributes["url.query"],
		statusCode: span.Attributes["http.response.status_code"],
	}
}

// cloneSpan creates a shallow copy of a span with a new Attributes map.
// H1 fix: prevents mutation of spans that may already be in the export pipeline.
func cloneSpan(s *Span) *Span {
	clone := *s
	clone.Attributes = make(map[string]string, len(s.Attributes))
	for k, v := range s.Attributes {
		clone.Attributes[k] = v
	}
	if len(s.Events) > 0 {
		clone.Events = make([]SpanEvent, len(s.Events))
		copy(clone.Events, s.Events)
	}
	return &clone
}

// pendingCount returns the total pending spans (must be called under s.mu).
func (s *Stitcher) pendingCount() int {
	count := 0
	for _, spans := range s.pendingClients {
		count += len(spans)
	}
	for _, spans := range s.pendingServers {
		count += len(spans)
	}
	return count
}

// Cleanup removes stale pending spans older than the window.
// Expired CLIENT clones are exported via callbacks (they were deferred
// from the normal export path to avoid orphaned duplicates).
func (s *Stitcher) Cleanup() int {
	s.mu.Lock()

	removed := 0
	cutoff := time.Now().Add(-2 * s.window)
	var expiredClients []*Span

	for key, spans := range s.pendingClients {
		kept := spans[:0]
		for _, ps := range spans {
			if ps.createdAt.After(cutoff) {
				kept = append(kept, ps)
			} else {
				// CLIENT clones were deferred — export them now unmatched.
				expiredClients = append(expiredClients, ps.span)
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

	// Must release lock before calling callbacks (they may call ExportSpan
	// which eventually calls back into this stitcher on another goroutine).
	cbs := s.callbacks
	s.mu.Unlock()

	// Export expired CLIENT clones so they don't get lost.
	for _, span := range expiredClients {
		for _, cb := range cbs {
			cb(span)
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
