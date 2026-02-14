// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package export

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unicode/utf8"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/traces"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	_ "google.golang.org/grpc/encoding/gzip" // Register gzip compressor

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// OTLPExporter sends telemetry via OTLP gRPC with automatic reconnection.
type OTLPExporter struct {
	logger         *zap.Logger
	serviceName    string
	serviceVersion string
	deploymentEnv  string
	endpoint       string
	opts           []grpc.DialOption

	mu        sync.RWMutex
	conn      *grpc.ClientConn
	traceSvc  coltracepb.TraceServiceClient
	logSvc    collogspb.LogsServiceClient
	metricSvc colmetricspb.MetricsServiceClient
}

// NewOTLPExporter creates a new OTLP gRPC exporter.
func NewOTLPExporter(cfg *config.OTLPConfig, serviceName, serviceVersion, deploymentEnv string, logger *zap.Logger) (*OTLPExporter, error) {
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(4 * 1024 * 1024)),
	}

	if cfg.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// Enable gzip compression for gRPC (default: gzip)
	if cfg.Compression == "" || cfg.Compression == "gzip" {
		opts = append(opts, grpc.WithDefaultCallOptions(grpc.UseCompressor("gzip")))
	}

	e := &OTLPExporter{
		logger:         logger,
		serviceName:    serviceName,
		serviceVersion: serviceVersion,
		deploymentEnv:  deploymentEnv,
		endpoint:       cfg.Endpoint,
		opts:           opts,
	}

	if err := e.connect(); err != nil {
		return nil, err
	}

	return e, nil
}

// connect establishes or re-establishes the gRPC connection.
func (e *OTLPExporter) connect() error {
	conn, err := grpc.Dial(e.endpoint, e.opts...)
	if err != nil {
		return fmt.Errorf("dial OTLP endpoint %s: %w", e.endpoint, err)
	}

	e.conn = conn
	e.traceSvc = coltracepb.NewTraceServiceClient(conn)
	e.logSvc = collogspb.NewLogsServiceClient(conn)
	e.metricSvc = colmetricspb.NewMetricsServiceClient(conn)

	return nil
}

// ensureConnected checks connection health and reconnects if needed.
func (e *OTLPExporter) ensureConnected() error {
	e.mu.RLock()
	conn := e.conn
	e.mu.RUnlock()

	if conn == nil {
		return e.reconnect()
	}

	state := conn.GetState()
	switch state {
	case connectivity.Ready, connectivity.Idle:
		return nil
	case connectivity.TransientFailure, connectivity.Shutdown:
		return e.reconnect()
	case connectivity.Connecting:
		// Let it finish connecting
		return nil
	default:
		return nil
	}
}

// reconnect closes the old connection and creates a new one.
func (e *OTLPExporter) reconnect() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check under write lock
	if e.conn != nil {
		state := e.conn.GetState()
		if state == connectivity.Ready || state == connectivity.Idle {
			return nil
		}
		e.conn.Close()
	}

	e.logger.Info("reconnecting to OTLP endpoint", zap.String("endpoint", e.endpoint))

	if err := e.connect(); err != nil {
		e.logger.Error("reconnect failed", zap.Error(err))
		return err
	}

	e.logger.Info("reconnected to OTLP endpoint")
	return nil
}

// resource returns the default OTEL resource for non-span signals (logs, metrics).
func (e *OTLPExporter) resource() *resourcepb.Resource {
	return e.resourceForService(e.serviceName, uint32(os.Getpid()))
}

// resourceForService returns OTEL resource attributes for a specific service.
// Each observed service gets its own ResourceSpans with accurate service.name
// and process attributes.
func (e *OTLPExporter) resourceForService(serviceName string, pid uint32) *resourcepb.Resource {
	hostname, _ := os.Hostname()

	if serviceName == "" {
		serviceName = e.serviceName
	}

	attrs := []*commonpb.KeyValue{
		strAttr("service.name", serviceName),
		strAttr("service.instance.id", fmt.Sprintf("%s-%d", hostname, pid)),
		strAttr("telemetry.sdk.name", "olly"),
		strAttr("telemetry.sdk.language", "go"),
		strAttr("telemetry.sdk.version", "0.1.0"),
		strAttr("host.name", hostname),
		strAttr("host.arch", runtime.GOARCH),
		strAttr("process.executable.name", serviceName),
		intAttr("process.pid", int64(pid)),
	}

	if e.serviceVersion != "" {
		attrs = append(attrs, strAttr("service.version", e.serviceVersion))
	}
	if e.deploymentEnv != "" {
		attrs = append(attrs, strAttr("deployment.environment", e.deploymentEnv))
	}

	return &resourcepb.Resource{Attributes: attrs}
}

func strAttr(key, value string) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}},
	}
}

func intAttr(key string, value int64) *commonpb.KeyValue {
	return &commonpb.KeyValue{
		Key:   key,
		Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: value}},
	}
}

// ExportSpans sends spans via OTLP gRPC, grouping by service name so each
// service gets its own ResourceSpans with accurate resource attributes.
func (e *OTLPExporter) ExportSpans(ctx context.Context, spans []*traces.Span) error {
	if len(spans) == 0 {
		return nil
	}

	if err := e.ensureConnected(); err != nil {
		return fmt.Errorf("connection not ready: %w", err)
	}

	// Group spans by service name for per-service ResourceSpans.
	type svcKey struct {
		name string
		pid  uint32
	}
	grouped := make(map[svcKey][]*tracepb.Span)
	for _, s := range spans {
		ps, err := e.convertSpan(s)
		if err != nil {
			e.logger.Debug("skip span conversion", zap.Error(err))
			continue
		}
		key := svcKey{name: s.ServiceName, pid: s.PID}
		grouped[key] = append(grouped[key], ps)
	}

	scope := &commonpb.InstrumentationScope{
		Name:    "olly",
		Version: "0.1.0",
	}

	resourceSpans := make([]*tracepb.ResourceSpans, 0, len(grouped))
	for key, protoSpans := range grouped {
		resourceSpans = append(resourceSpans, &tracepb.ResourceSpans{
			Resource: e.resourceForService(key.name, key.pid),
			ScopeSpans: []*tracepb.ScopeSpans{
				{
					Scope: scope,
					Spans: protoSpans,
				},
			},
		})
	}

	req := &coltracepb.ExportTraceServiceRequest{
		ResourceSpans: resourceSpans,
	}

	e.mu.RLock()
	svc := e.traceSvc
	e.mu.RUnlock()

	_, err := svc.Export(ctx, req)
	return err
}

func (e *OTLPExporter) convertSpan(s *traces.Span) (*tracepb.Span, error) {
	traceID, err := hexToBytes(s.TraceID, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid trace ID: %w", err)
	}

	spanID, err := hexToBytes(s.SpanID, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid span ID: %w", err)
	}

	ps := &tracepb.Span{
		TraceId:           traceID,
		SpanId:            spanID,
		TraceState:        sanitizeUTF8(s.TraceState),
		Name:              sanitizeUTF8(s.Name),
		Kind:              convertSpanKind(s.Kind),
		StartTimeUnixNano: uint64(s.StartTime.UnixNano()),
		EndTimeUnixNano:   uint64(s.EndTime.UnixNano()),
	}

	if s.ParentSpanID != "" {
		parentID, err := hexToBytes(s.ParentSpanID, 8)
		if err == nil {
			ps.ParentSpanId = parentID
		}
	}

	// Status (S1 fix: StatusUnset maps to UNSET, not OK)
	ps.Status = &tracepb.Status{}
	switch s.Status {
	case traces.StatusOK:
		ps.Status.Code = tracepb.Status_STATUS_CODE_OK
	case traces.StatusError:
		ps.Status.Code = tracepb.Status_STATUS_CODE_ERROR
		ps.Status.Message = sanitizeUTF8(s.StatusMsg)
	default:
		ps.Status.Code = tracepb.Status_STATUS_CODE_UNSET
	}

	// Attributes — sanitize values to valid UTF-8 (eBPF payloads may contain binary data)
	for k, v := range s.Attributes {
		ps.Attributes = append(ps.Attributes, &commonpb.KeyValue{
			Key:   k,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: sanitizeUTF8(v)}},
		})
	}

	// Events
	for _, ev := range s.Events {
		pe := &tracepb.Span_Event{
			Name:         sanitizeUTF8(ev.Name),
			TimeUnixNano: uint64(ev.Timestamp.UnixNano()),
		}
		for k, v := range ev.Attributes {
			pe.Attributes = append(pe.Attributes, &commonpb.KeyValue{
				Key:   k,
				Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: sanitizeUTF8(v)}},
			})
		}
		ps.Events = append(ps.Events, pe)
	}

	return ps, nil
}

// convertLogRecord converts a single LogRecord to its protobuf representation.
func (e *OTLPExporter) convertLogRecord(l *LogRecord) *logspb.LogRecord {
	pl := &logspb.LogRecord{
		TimeUnixNano: uint64(l.Timestamp.UnixNano()),
		Body: &commonpb.AnyValue{
			Value: &commonpb.AnyValue_StringValue{StringValue: sanitizeUTF8(l.Body)},
		},
		SeverityText:   l.Level,
		SeverityNumber: logspb.SeverityNumber(l.SeverityNumber), // R3.1
	}

	// R3.2: Set ObservedTimestamp (when collector received the log)
	if !l.ObservedTime.IsZero() {
		pl.ObservedTimeUnixNano = uint64(l.ObservedTime.UnixNano())
	}

	if l.TraceID != "" {
		if tid, err := hexToBytes(l.TraceID, 16); err == nil {
			pl.TraceId = tid
			// R3.3: Set TraceFlags when correlated
			pl.Flags = 0x01 // sampled
		}
	}
	if l.SpanID != "" {
		if sid, err := hexToBytes(l.SpanID, 8); err == nil {
			pl.SpanId = sid
		}
	}

	// R3.4: Add log source attributes
	// Clone attributes to avoid mutating the input (B4 fix: race between exporters)
	attrs := make(map[string]interface{}, len(l.Attributes)+5)
	for k, v := range l.Attributes {
		attrs[k] = v
	}
	if l.FilePath != "" {
		attrs["log.file.path"] = l.FilePath
		attrs["log.file.name"] = filepath.Base(l.FilePath)
	}
	if l.Source != "" {
		attrs["source"] = l.Source
	}
	// Also add trace context as attributes for Loki/Grafana compatibility.
	// The OTLP proto traceId/spanId fields are stored in Loki structured
	// metadata, but attributes are more reliably surfaced as detected fields.
	if l.TraceID != "" {
		attrs["trace_id"] = l.TraceID
	}
	if l.SpanID != "" {
		attrs["span_id"] = l.SpanID
	}

	for k, v := range attrs {
		pl.Attributes = append(pl.Attributes, &commonpb.KeyValue{
			Key:   k,
			Value: toAnyValue(v),
		})
	}

	return pl
}

// ExportLogs sends log records via OTLP gRPC, grouping by service name
// so each service gets its own ResourceLogs with accurate resource attributes.
func (e *OTLPExporter) ExportLogs(ctx context.Context, logs []*LogRecord) error {
	if len(logs) == 0 {
		return nil
	}

	if err := e.ensureConnected(); err != nil {
		return fmt.Errorf("connection not ready: %w", err)
	}

	// Group logs by service name for per-service ResourceLogs.
	type svcKey struct {
		name string
		pid  int
	}
	grouped := make(map[svcKey][]*logspb.LogRecord)
	for _, l := range logs {
		pl := e.convertLogRecord(l)
		key := svcKey{name: l.ServiceName, pid: l.PID}
		grouped[key] = append(grouped[key], pl)
	}

	scope := &commonpb.InstrumentationScope{
		Name:    "olly",
		Version: "0.1.0",
	}

	resourceLogs := make([]*logspb.ResourceLogs, 0, len(grouped))
	for key, protoLogs := range grouped {
		resourceLogs = append(resourceLogs, &logspb.ResourceLogs{
			Resource: e.resourceForService(key.name, uint32(key.pid)),
			ScopeLogs: []*logspb.ScopeLogs{
				{
					Scope:      scope,
					LogRecords: protoLogs,
				},
			},
		})
	}

	req := &collogspb.ExportLogsServiceRequest{
		ResourceLogs: resourceLogs,
	}

	e.mu.RLock()
	svc := e.logSvc
	e.mu.RUnlock()

	_, err := svc.Export(ctx, req)
	return err
}

// ExportMetrics sends metrics via OTLP gRPC, grouping by service name
// so each service gets its own ResourceMetrics with accurate resource attributes.
func (e *OTLPExporter) ExportMetrics(ctx context.Context, metrics []*Metric) error {
	if len(metrics) == 0 {
		return nil
	}

	if err := e.ensureConnected(); err != nil {
		return fmt.Errorf("connection not ready: %w", err)
	}

	// Group metrics by service name for per-service ResourceMetrics.
	grouped := make(map[string][]*metricspb.Metric)
	for _, m := range metrics {
		pm := e.convertMetric(m)
		if pm != nil {
			grouped[m.ServiceName] = append(grouped[m.ServiceName], pm)
		}
	}

	scope := &commonpb.InstrumentationScope{
		Name:    "olly",
		Version: "0.1.0",
	}

	resourceMetrics := make([]*metricspb.ResourceMetrics, 0, len(grouped))
	for svcName, protoMetrics := range grouped {
		resourceMetrics = append(resourceMetrics, &metricspb.ResourceMetrics{
			Resource: e.resourceForService(svcName, uint32(os.Getpid())),
			ScopeMetrics: []*metricspb.ScopeMetrics{
				{
					Scope:   scope,
					Metrics: protoMetrics,
				},
			},
		})
	}

	req := &colmetricspb.ExportMetricsServiceRequest{
		ResourceMetrics: resourceMetrics,
	}

	e.mu.RLock()
	svc := e.metricSvc
	e.mu.RUnlock()

	_, err := svc.Export(ctx, req)
	return err
}

func (e *OTLPExporter) convertMetric(m *Metric) *metricspb.Metric {
	pm := &metricspb.Metric{
		Name:        m.Name,
		Description: m.Description,
		Unit:        m.Unit,
	}

	attrs := make([]*commonpb.KeyValue, 0, len(m.Labels))
	for k, v := range m.Labels {
		attrs = append(attrs, &commonpb.KeyValue{
			Key:   k,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: v}},
		})
	}

	ts := uint64(m.Timestamp.UnixNano())

	// StartTimeUnixNano for cumulative data points (Sum, Histogram)
	var startTs uint64
	if !m.StartTime.IsZero() {
		startTs = uint64(m.StartTime.UnixNano())
	}

	switch m.Type {
	case MetricGauge:
		pm.Data = &metricspb.Metric_Gauge{
			Gauge: &metricspb.Gauge{
				DataPoints: []*metricspb.NumberDataPoint{
					{
						TimeUnixNano: ts,
						Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: m.Value},
						Attributes:   attrs,
					},
				},
			},
		}

	case MetricCounter:
		pm.Data = &metricspb.Metric_Sum{
			Sum: &metricspb.Sum{
				IsMonotonic:            true,
				AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
				DataPoints: []*metricspb.NumberDataPoint{
					{
						StartTimeUnixNano: startTs,
						TimeUnixNano:      ts,
						Value:             &metricspb.NumberDataPoint_AsDouble{AsDouble: m.Value},
						Attributes:        attrs,
					},
				},
			},
		}

	case MetricHistogram:
		if m.Histogram != nil {
			// R5.2: OTLP requires len(BucketCounts) == len(ExplicitBounds) + 1
			// The last bucket count is the +Inf overflow bucket.
			nBuckets := len(m.Histogram.Buckets)
			bounds := make([]float64, nBuckets)
			counts := make([]uint64, nBuckets+1) // +1 for +Inf overflow
			for i, b := range m.Histogram.Buckets {
				bounds[i] = b.UpperBound
				counts[i] = b.Count
			}
			// +Inf bucket: total count minus the cumulative count in the last explicit bucket
			if nBuckets > 0 {
				counts[nBuckets] = m.Histogram.Count - counts[nBuckets-1]
			} else {
				counts[0] = m.Histogram.Count
			}

			pm.Data = &metricspb.Metric_Histogram{
				Histogram: &metricspb.Histogram{
					AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
					DataPoints: []*metricspb.HistogramDataPoint{
						{
							StartTimeUnixNano: startTs,
							TimeUnixNano:      ts,
							Count:             m.Histogram.Count,
							Sum:               &m.Histogram.Sum,
							ExplicitBounds:    bounds,
							BucketCounts:      counts,
							Attributes:        attrs,
						},
					},
				},
			}
		}
	}

	return pm
}

// Shutdown closes the gRPC connection.
func (e *OTLPExporter) Shutdown(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.conn != nil {
		return e.conn.Close()
	}
	return nil
}

// sanitizeUTF8 replaces invalid UTF-8 sequences with the Unicode replacement
// character. eBPF-captured payloads may contain encrypted TLS bytes or truncated
// multi-byte sequences that are not valid UTF-8, causing gRPC protobuf marshaling
// to fail.
func sanitizeUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	return string([]rune(s))
}

func hexToBytes(s string, expectedLen int) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != expectedLen {
		return nil, fmt.Errorf("expected %d bytes, got %d", expectedLen, len(b))
	}
	return b, nil
}

func convertSpanKind(k traces.SpanKind) tracepb.Span_SpanKind {
	switch k {
	case traces.SpanKindServer:
		return tracepb.Span_SPAN_KIND_SERVER
	case traces.SpanKindClient:
		return tracepb.Span_SPAN_KIND_CLIENT
	case traces.SpanKindProducer:
		return tracepb.Span_SPAN_KIND_PRODUCER
	case traces.SpanKindConsumer:
		return tracepb.Span_SPAN_KIND_CONSUMER
	default:
		return tracepb.Span_SPAN_KIND_INTERNAL
	}
}

func toAnyValue(v interface{}) *commonpb.AnyValue {
	switch val := v.(type) {
	case string:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: val}}
	case int:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(val)}}
	case int64:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: val}}
	case float64:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: val}}
	case bool:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: val}}
	default:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: fmt.Sprintf("%v", val)}}
	}
}
