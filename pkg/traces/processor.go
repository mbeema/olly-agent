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

	// Parse request/response
	attrs, err := protocol.Parse(proto, pair.Request, pair.Response)
	if err != nil {
		p.logger.Debug("parse error", zap.String("protocol", proto), zap.Error(err))
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

	// Try to extract trace context from HTTP headers (R1.2: include tracestate)
	if proto == protocol.ProtoHTTP || proto == protocol.ProtoGRPC {
		traceCtx := protocol.ExtractTraceContext(pair.Request)
		if traceCtx.TraceID != "" {
			span.TraceID = traceCtx.TraceID
			span.ParentSpanID = traceCtx.SpanID
			span.SpanID = GenerateSpanID()
			span.TraceState = traceCtx.TraceState
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
			} else {
				span.SpanID = GenerateSpanID()
			}
			span.ParentSpanID = pair.ParentSpanID
		} else {
			// SERVER span: use ParentSpanID as this span's own ID so
			// CLIENT child spans can reference it as their parent.
			if span.TraceID == "" {
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

	// Set status
	if attrs.Error {
		span.Status = StatusError
		span.StatusMsg = attrs.ErrorMsg
	} else {
		span.Status = StatusOK
	}

	// Set connection info (R2.1: stable semantic conventions)
	if connInfo != nil {
		span.RemoteAddr = connInfo.RemoteAddrStr()
		span.RemotePort = connInfo.RemotePort
		span.IsSSL = connInfo.IsSSL
		span.SetAttribute("network.peer.address", connInfo.RemoteAddrStr())
		span.SetAttribute("network.peer.port", fmt.Sprintf("%d", connInfo.RemotePort))
	}

	// Set protocol-specific attributes
	p.setProtocolAttributes(span, attrs, pair.IsSSL, connInfo)

	// Set common attributes
	span.SetAttribute("process.pid", fmt.Sprintf("%d", pair.PID))
	span.SetAttribute("thread.id", fmt.Sprintf("%d", pair.TID))
	if pair.IsSSL {
		span.SetAttribute("network.transport", "tcp")
	} else {
		span.SetAttribute("network.transport", "tcp")
	}

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
		if attrs.HTTPStatusCode > 0 {
			span.SetAttribute("http.response.status_code", fmt.Sprintf("%d", attrs.HTTPStatusCode))
		}
		if attrs.HTTPHost != "" {
			span.SetAttribute("server.address", attrs.HTTPHost)
		}
		if attrs.HTTPUserAgent != "" {
			span.SetAttribute("user_agent.original", attrs.HTTPUserAgent)
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
		// Add server address from connection info
		if connInfo != nil {
			span.SetAttribute("server.address", connInfo.RemoteAddrStr())
			span.SetAttribute("server.port", fmt.Sprintf("%d", connInfo.RemotePort))
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
		}

	case protocol.ProtoGRPC:
		if attrs.GRPCService != "" {
			span.SetAttribute("rpc.system", "grpc")
			span.SetAttribute("rpc.service", attrs.GRPCService)
			span.SetAttribute("rpc.method", attrs.GRPCMethod)
		}
		if attrs.GRPCStatus != 0 {
			span.SetAttribute("rpc.grpc.status_code", fmt.Sprintf("%d", attrs.GRPCStatus))
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
