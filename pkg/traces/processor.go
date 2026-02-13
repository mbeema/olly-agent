// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package traces

import (
	"fmt"
	"sync"
	"time"

	"github.com/mbeema/olly/pkg/conntrack"
	"github.com/mbeema/olly/pkg/protocol"
	"github.com/mbeema/olly/pkg/reassembly"
	"go.uber.org/zap"
)

// Processor converts request/response pairs into OTEL spans.
type Processor struct {
	logger    *zap.Logger
	mu        sync.RWMutex
	callbacks []func(*Span)
}

// NewProcessor creates a new trace processor.
func NewProcessor(logger *zap.Logger) *Processor {
	return &Processor{
		logger: logger,
	}
}

// OnSpan registers a callback for completed spans.
func (p *Processor) OnSpan(fn func(*Span)) {
	p.mu.Lock()
	p.callbacks = append(p.callbacks, fn)
	p.mu.Unlock()
}

func (p *Processor) emitSpan(span *Span) {
	p.mu.RLock()
	cbs := p.callbacks
	p.mu.RUnlock()

	for _, cb := range cbs {
		cb(span)
	}
}

// ProcessPair processes a request/response pair and emits a span.
func (p *Processor) ProcessPair(pair *reassembly.RequestPair, connInfo *conntrack.ConnInfo) {
	if pair == nil {
		return
	}

	// Detect protocol
	proto := pair.Protocol
	if proto == "" {
		proto = protocol.Detect(pair.Request, pair.RemotePort)
	}

	// Refine protocol: promote "http" → "genai" when GenAI endpoint detected
	proto = protocol.Refine(proto, pair.Request, pair.RemotePort)

	// Parse request/response
	// Note: agent.go already swaps send/recv for inbound (SERVER) connections,
	// so pair.Request always contains the request and pair.Response the response.
	attrs, err := protocol.Parse(proto, pair.Request, pair.Response)
	if err != nil {
		p.logger.Debug("parse error", zap.String("protocol", proto), zap.Error(err))
		return
	}

	// Skip handshake/admin commands (e.g., MongoDB isMaster/hello)
	if attrs.Handshake {
		return
	}

	// R2.3 fix: Determine span kind from connection direction.
	// Inbound (accept) → SERVER, Outbound (connect) → CLIENT.
	// Use pair.Direction which is preserved from stream creation, surviving connection close.
	kind := SpanKindClient
	if pair.Direction == 1 { // 1=inbound
		kind = SpanKindServer
	} else if connInfo != nil && connInfo.Direction == conntrack.ConnInbound {
		kind = SpanKindServer
	}

	// Build span
	span := &Span{
		Name:        attrs.Name,
		Kind:        kind,
		StartTime:   pair.RequestTime,
		EndTime:     pair.RequestTime.Add(pair.Duration),
		Duration:    pair.Duration,
		PID:         pair.PID,
		TID:         pair.TID,
		RemoteAddr:  pair.RemoteAddr,
		RemotePort:  pair.RemotePort,
		IsSSL:       pair.IsSSL,
		Protocol:    proto,
		Attributes:  make(map[string]string),
	}

	// Try to extract trace context from HTTP headers (R1.2: include tracestate).
	// This covers: (a) traceparent injected by upstream sk_msg, (b) app-level headers.
	if proto == protocol.ProtoHTTP || proto == protocol.ProtoGRPC || proto == protocol.ProtoGenAI || proto == protocol.ProtoMCP {
		traceCtx := protocol.ExtractTraceContext(pair.Request)
		if traceCtx.TraceID != "" {
			span.TraceID = traceCtx.TraceID
			span.ParentSpanID = traceCtx.SpanID
			span.SpanID = GenerateSpanID()
			span.TraceState = traceCtx.TraceState
			span.SetAttribute("olly.trace_source", "traceparent")
		}
	}

	// Intra-process parent-child linking: if a parent context was set from
	// the inbound request on this PID+TID, use it for trace correlation.
	// Creates a proper chain: SERVER(ParentSpanID) → CLIENT(InjectedSpanID) → downstream
	if pair.ParentTraceID != "" {
		if kind == SpanKindClient {
			// CLIENT span: use thread context for parent linkage.
			// InjectedSpanID is what sk_msg injected into the outbound HTTP,
			// so the downstream service's parentSpanID matches this CLIENT span.
			span.TraceID = pair.ParentTraceID
			if pair.InjectedSpanID != "" {
				span.SpanID = pair.InjectedSpanID
				// Mark as linked via traceparent injection so the stitcher
				// knows this CLIENT→SERVER link is already established and
				// doesn't defer this span waiting for a SERVER match.
				span.SetAttribute("olly.trace_source", "injected")
			} else {
				span.SpanID = GenerateSpanID()
			}
			span.ParentSpanID = pair.ParentSpanID
		} else {
			// SERVER span: use thread context for SpanID (so child CLIENT
			// spans can reference it as parent). Only overwrite TraceID if
			// traceparent wasn't extracted — when extraction succeeds, the
			// extracted traceID is authoritative (from the upstream service).
			// Thread context traceID may differ (BPF-generated) if the
			// traceparent was split across reads or reassembled in the pair.
			if span.Attributes["olly.trace_source"] != "traceparent" {
				span.TraceID = pair.ParentTraceID
			}
			span.SpanID = pair.ParentSpanID
		}
	}

	// Generate IDs if not extracted from headers
	if span.TraceID == "" {
		span.TraceID = GenerateTraceID()
		span.SpanID = GenerateSpanID()
	}

	// Set status (S1 fix: use StatusUnset for success per OTEL spec, not StatusOK)
	if attrs.Error {
		// S2 fix: HTTP SERVER spans with 4xx are NOT errors per OTEL spec.
		// The server handled the request correctly; only 5xx is an error.
		if span.Kind == SpanKindServer && attrs.HTTPStatusCode >= 400 && attrs.HTTPStatusCode < 500 {
			span.Status = StatusUnset
		} else {
			span.Status = StatusError
			span.StatusMsg = attrs.ErrorMsg
		}
	} else {
		span.Status = StatusUnset
	}

	// Set connection info (R2.1: stable semantic conventions).
	// Fallback to pair's RemoteAddr/RemotePort when connInfo is nil.
	// This happens when OnClose removes the connection from the tracker
	// before pairDispatchLoop processes the pair (race on connection close).
	if connInfo != nil {
		span.RemoteAddr = connInfo.RemoteAddrStr()
		span.RemotePort = connInfo.RemotePort
		span.IsSSL = connInfo.IsSSL
		span.SetAttribute("network.peer.address", connInfo.RemoteAddrStr())
		span.SetAttribute("network.peer.port", fmt.Sprintf("%d", connInfo.RemotePort))
	} else if pair.RemoteAddr != "" {
		span.SetAttribute("network.peer.address", pair.RemoteAddr)
		span.SetAttribute("network.peer.port", fmt.Sprintf("%d", pair.RemotePort))
	}

	// Set protocol-specific attributes
	p.setProtocolAttributes(span, attrs, pair.IsSSL, connInfo)

	// Set common attributes
	span.SetAttribute("process.pid", fmt.Sprintf("%d", pair.PID))
	span.SetAttribute("thread.id", fmt.Sprintf("%d", pair.TID))
	span.SetAttribute("network.transport", "tcp")

	p.emitSpan(span)
}

func (p *Processor) setProtocolAttributes(span *Span, attrs *protocol.SpanAttributes, isSSL bool, connInfo *conntrack.ConnInfo) {
	switch attrs.Protocol {
	case protocol.ProtoHTTP:
		// R2.1: Stable HTTP semantic conventions (v1.23+)
		if attrs.HTTPMethod != "" {
			span.SetAttribute("http.request.method", attrs.HTTPMethod)
		}
		if attrs.HTTPPath != "" {
			span.SetAttribute("url.path", attrs.HTTPPath)
		}
		// H3 fix: url.query separated from url.path
		if attrs.HTTPQuery != "" {
			span.SetAttribute("url.query", attrs.HTTPQuery)
		}
		if attrs.HTTPStatusCode > 0 {
			span.SetAttribute("http.response.status_code", fmt.Sprintf("%d", attrs.HTTPStatusCode))
		}
		if attrs.HTTPHost != "" {
			span.SetAttribute("server.address", attrs.HTTPHost)
		}
		if attrs.HTTPUserAgent != "" {
			span.SetAttribute("user_agent.original", attrs.HTTPUserAgent)
		}
		// S7 fix: server.port for HTTP spans
		if connInfo != nil {
			span.SetAttribute("server.port", fmt.Sprintf("%d", connInfo.RemotePort))
		}
		// url.scheme from SSL detection
		if isSSL {
			span.SetAttribute("url.scheme", "https")
		} else {
			span.SetAttribute("url.scheme", "http")
		}
		// error.type on error spans
		if attrs.Error && attrs.HTTPStatusCode >= 400 {
			span.SetAttribute("error.type", fmt.Sprintf("%d", attrs.HTTPStatusCode))
		}

	case protocol.ProtoPostgres, protocol.ProtoMySQL:
		// R2.2: Stable DB semantic conventions
		if attrs.DBSystem != "" {
			span.SetAttribute("db.system", attrs.DBSystem)
		}
		if attrs.DBStatement != "" {
			stmt := attrs.DBStatement
			if len(stmt) > 1024 {
				stmt = stmt[:1024] + "..."
			}
			span.SetAttribute("db.query.text", stmt)
		}
		if attrs.DBOperation != "" {
			span.SetAttribute("db.operation.name", attrs.DBOperation)
		}
		if attrs.DBName != "" {
			span.SetAttribute("db.namespace", attrs.DBName)
		}
		// Add server address from connection info, fallback to span's remote info
		if connInfo != nil {
			span.SetAttribute("server.address", connInfo.RemoteAddrStr())
			span.SetAttribute("server.port", fmt.Sprintf("%d", connInfo.RemotePort))
		} else if span.RemoteAddr != "" {
			span.SetAttribute("server.address", span.RemoteAddr)
			span.SetAttribute("server.port", fmt.Sprintf("%d", span.RemotePort))
		}

	case protocol.ProtoRedis:
		span.SetAttribute("db.system", "redis")
		if attrs.RedisCommand != "" {
			span.SetAttribute("db.operation.name", attrs.RedisCommand)
		}
		if attrs.DBStatement != "" {
			span.SetAttribute("db.query.text", attrs.DBStatement)
		}
		if connInfo != nil {
			span.SetAttribute("server.address", connInfo.RemoteAddrStr())
			span.SetAttribute("server.port", fmt.Sprintf("%d", connInfo.RemotePort))
		} else if span.RemoteAddr != "" {
			span.SetAttribute("server.address", span.RemoteAddr)
			span.SetAttribute("server.port", fmt.Sprintf("%d", span.RemotePort))
		}

	case protocol.ProtoMongoDB:
		span.SetAttribute("db.system", "mongodb")
		if attrs.DBOperation != "" {
			span.SetAttribute("db.operation.name", attrs.DBOperation)
		}
		if attrs.DBName != "" {
			span.SetAttribute("db.collection.name", attrs.DBName)
		}
		if connInfo != nil {
			span.SetAttribute("server.address", connInfo.RemoteAddrStr())
			span.SetAttribute("server.port", fmt.Sprintf("%d", connInfo.RemotePort))
		} else if span.RemoteAddr != "" {
			span.SetAttribute("server.address", span.RemoteAddr)
			span.SetAttribute("server.port", fmt.Sprintf("%d", span.RemotePort))
		}

	case protocol.ProtoGRPC:
		// S4 fix: always set rpc.system regardless of service detection
		span.SetAttribute("rpc.system", "grpc")
		if attrs.GRPCService != "" {
			span.SetAttribute("rpc.service", attrs.GRPCService)
		}
		if attrs.GRPCMethod != "" {
			span.SetAttribute("rpc.method", attrs.GRPCMethod)
		}
		// S3 fix: always set status_code, even for OK (0)
		span.SetAttribute("rpc.grpc.status_code", fmt.Sprintf("%d", attrs.GRPCStatus))
		// S5 fix: add server.address/port for gRPC
		if connInfo != nil {
			span.SetAttribute("server.address", connInfo.RemoteAddrStr())
			span.SetAttribute("server.port", fmt.Sprintf("%d", connInfo.RemotePort))
		} else if span.RemoteAddr != "" {
			span.SetAttribute("server.address", span.RemoteAddr)
			span.SetAttribute("server.port", fmt.Sprintf("%d", span.RemotePort))
		}

	case protocol.ProtoDNS:
		if attrs.DNSName != "" {
			span.SetAttribute("dns.question.name", attrs.DNSName)
		}
		if attrs.DNSType != "" {
			span.SetAttribute("dns.question.type", attrs.DNSType)
		}
		if attrs.DNSRcode != "" {
			span.SetAttribute("dns.response_code", attrs.DNSRcode)
		}
		if attrs.DNSAnswers > 0 {
			span.SetAttribute("dns.answers", fmt.Sprintf("%d", attrs.DNSAnswers))
		}

	case protocol.ProtoGenAI:
		// OTEL GenAI semantic conventions (gen_ai.* namespace)
		if attrs.GenAIProvider != "" {
			span.SetAttribute("gen_ai.system", attrs.GenAIProvider)
		}
		if attrs.GenAIOperation != "" {
			span.SetAttribute("gen_ai.operation.name", attrs.GenAIOperation)
		}
		if attrs.GenAIRequestModel != "" {
			span.SetAttribute("gen_ai.request.model", attrs.GenAIRequestModel)
		}
		if attrs.GenAIResponseModel != "" {
			span.SetAttribute("gen_ai.response.model", attrs.GenAIResponseModel)
		}
		if attrs.GenAIResponseID != "" {
			span.SetAttribute("gen_ai.response.id", attrs.GenAIResponseID)
		}
		if attrs.GenAIInputTokensSet {
			span.SetAttribute("gen_ai.usage.input_tokens", fmt.Sprintf("%d", attrs.GenAIInputTokens))
		}
		if attrs.GenAIOutputTokensSet {
			span.SetAttribute("gen_ai.usage.output_tokens", fmt.Sprintf("%d", attrs.GenAIOutputTokens))
		}
		if attrs.GenAIFinishReason != "" {
			span.SetAttribute("gen_ai.response.finish_reasons", attrs.GenAIFinishReason)
		}
		if attrs.GenAITemperatureSet {
			span.SetAttribute("gen_ai.request.temperature", fmt.Sprintf("%.2f", attrs.GenAITemperature))
		}
		if attrs.GenAITopPSet {
			span.SetAttribute("gen_ai.request.top_p", fmt.Sprintf("%.2f", attrs.GenAITopP))
		}
		if attrs.GenAIMaxTokensSet {
			span.SetAttribute("gen_ai.request.max_tokens", fmt.Sprintf("%d", attrs.GenAIMaxTokens))
		}
		if attrs.GenAIStreaming {
			span.SetAttribute("gen_ai.request.streaming", "true")
		}
		// Underlying HTTP attributes
		if attrs.HTTPMethod != "" {
			span.SetAttribute("http.request.method", attrs.HTTPMethod)
		}
		if attrs.HTTPStatusCode > 0 {
			span.SetAttribute("http.response.status_code", fmt.Sprintf("%d", attrs.HTTPStatusCode))
		}
		if attrs.HTTPHost != "" {
			span.SetAttribute("server.address", attrs.HTTPHost)
		}
		if connInfo != nil {
			span.SetAttribute("server.port", fmt.Sprintf("%d", connInfo.RemotePort))
		}
		if isSSL {
			span.SetAttribute("url.scheme", "https")
		} else {
			span.SetAttribute("url.scheme", "http")
		}
		if attrs.Error && attrs.HTTPStatusCode >= 400 {
			span.SetAttribute("error.type", fmt.Sprintf("%d", attrs.HTTPStatusCode))
		}

	case protocol.ProtoMCP:
		// MCP (Model Context Protocol) - JSON-RPC 2.0 over HTTP
		if attrs.MCPMethod != "" {
			span.SetAttribute("mcp.method", attrs.MCPMethod)
		}
		if attrs.MCPRequestID != "" {
			span.SetAttribute("mcp.request.id", attrs.MCPRequestID)
		}
		if attrs.MCPToolName != "" {
			span.SetAttribute("mcp.tool.name", attrs.MCPToolName)
		}
		if attrs.MCPResourceURI != "" {
			span.SetAttribute("mcp.resource.uri", attrs.MCPResourceURI)
		}
		if attrs.MCPPromptName != "" {
			span.SetAttribute("mcp.prompt.name", attrs.MCPPromptName)
		}
		if attrs.MCPSessionID != "" {
			span.SetAttribute("mcp.session.id", attrs.MCPSessionID)
		}
		if attrs.MCPTransport != "" {
			span.SetAttribute("mcp.transport", attrs.MCPTransport)
		}
		if attrs.MCPErrorCode != 0 {
			span.SetAttribute("mcp.error.code", fmt.Sprintf("%d", attrs.MCPErrorCode))
		}
		if attrs.MCPErrorMsg != "" {
			span.SetAttribute("mcp.error.message", attrs.MCPErrorMsg)
		}
		// Underlying HTTP attributes
		if attrs.HTTPMethod != "" {
			span.SetAttribute("http.request.method", attrs.HTTPMethod)
		}
		if attrs.HTTPPath != "" {
			span.SetAttribute("url.path", attrs.HTTPPath)
		}
		if attrs.HTTPStatusCode > 0 {
			span.SetAttribute("http.response.status_code", fmt.Sprintf("%d", attrs.HTTPStatusCode))
		}
		if attrs.HTTPHost != "" {
			span.SetAttribute("server.address", attrs.HTTPHost)
		}
		if connInfo != nil {
			span.SetAttribute("server.port", fmt.Sprintf("%d", connInfo.RemotePort))
		}
		if isSSL {
			span.SetAttribute("url.scheme", "https")
		} else {
			span.SetAttribute("url.scheme", "http")
		}
		if attrs.Error && attrs.HTTPStatusCode >= 400 {
			span.SetAttribute("error.type", fmt.Sprintf("%d", attrs.HTTPStatusCode))
		}
	}
}

// ProcessTimeout creates a span for a connection that timed out waiting for response.
func (p *Processor) ProcessTimeout(pid, tid uint32, connInfo *conntrack.ConnInfo, request []byte, startTime time.Time) {
	if connInfo == nil {
		return
	}

	span := &Span{
		TraceID:    GenerateTraceID(),
		SpanID:     GenerateSpanID(),
		Name:       "timeout",
		Kind:       SpanKindClient,
		StartTime:  startTime,
		EndTime:    time.Now(),
		Duration:   time.Since(startTime),
		Status:     StatusError,
		StatusMsg:  "connection timeout",
		PID:        pid,
		TID:        tid,
		RemoteAddr: connInfo.RemoteAddrStr(),
		RemotePort: connInfo.RemotePort,
		Attributes: map[string]string{
			"network.peer.address": connInfo.RemoteAddrStr(),
			"network.peer.port":    fmt.Sprintf("%d", connInfo.RemotePort),
			"error.type":           "timeout",
		},
	}

	p.emitSpan(span)
}
