package traces

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// SpanKind identifies the relationship of a span to its parent.
type SpanKind int

const (
	SpanKindInternal SpanKind = iota
	SpanKindServer
	SpanKindClient
	SpanKindProducer
	SpanKindConsumer
)

func (k SpanKind) String() string {
	switch k {
	case SpanKindServer:
		return "SERVER"
	case SpanKindClient:
		return "CLIENT"
	case SpanKindProducer:
		return "PRODUCER"
	case SpanKindConsumer:
		return "CONSUMER"
	default:
		return "INTERNAL"
	}
}

// StatusCode represents the span status.
type StatusCode int

const (
	StatusUnset StatusCode = iota
	StatusOK
	StatusError
)

// Span represents an OTEL-compatible trace span.
type Span struct {
	TraceID      string
	SpanID       string
	ParentSpanID string
	TraceState   string // W3C tracestate header value (R1.2)
	Name         string
	Kind         SpanKind
	StartTime    time.Time
	EndTime      time.Time
	Duration     time.Duration
	Status       StatusCode
	StatusMsg    string

	// Service info
	ServiceName string
	PID         uint32
	TID         uint32

	// Network info
	RemoteAddr string
	RemotePort uint16
	IsSSL      bool
	Protocol   string

	// Attributes (OTEL standard)
	Attributes map[string]string

	// Events (for errors, etc.)
	Events []SpanEvent
}

// SpanEvent is a timestamped event within a span.
type SpanEvent struct {
	Name       string
	Timestamp  time.Time
	Attributes map[string]string
}

// NewSpan creates a new span with generated IDs.
func NewSpan(name string, kind SpanKind) *Span {
	now := time.Now()
	return &Span{
		TraceID:    GenerateTraceID(),
		SpanID:     GenerateSpanID(),
		Name:       name,
		Kind:       kind,
		StartTime:  now,
		Attributes: make(map[string]string),
	}
}

// End marks the span as complete.
func (s *Span) End() {
	s.EndTime = time.Now()
	s.Duration = s.EndTime.Sub(s.StartTime)
}

// SetAttribute sets a span attribute.
func (s *Span) SetAttribute(key, value string) {
	if s.Attributes == nil {
		s.Attributes = make(map[string]string)
	}
	s.Attributes[key] = value
}

// SetError marks the span as errored with a message.
func (s *Span) SetError(msg string) {
	s.Status = StatusError
	s.StatusMsg = msg
	s.Events = append(s.Events, SpanEvent{
		Name:      "exception",
		Timestamp: time.Now(),
		Attributes: map[string]string{
			"exception.message": msg,
		},
	})
}

// GenerateTraceID generates a random 32-character hex trace ID.
func GenerateTraceID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateSpanID generates a random 16-character hex span ID.
func GenerateSpanID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// TraceParent formats the W3C traceparent header value.
// R1.5 fix: The sampled flag (01) indicates the trace is being recorded.
// Since Olly records all traces, the flag is always 01. Error status is
// conveyed through span status, not trace-flags.
func (s *Span) TraceParent() string {
	// Bit 0 = sampled (trace is being recorded)
	// Bit 1 = random (trace-id generated with randomness) - W3C Level 2
	// Olly always records and generates random trace IDs → flags = 03
	return "00-" + s.TraceID + "-" + s.SpanID + "-" + "03"
}
