// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package export

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/traces"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// HTTPOTLPExporter sends telemetry via OTLP HTTP/protobuf.
type HTTPOTLPExporter struct {
	logger         *zap.Logger
	serviceName    string
	serviceVersion string
	deploymentEnv  string
	endpoint       string
	compression    string
	headers        map[string]string
	client         *http.Client
}

// NewHTTPOTLPExporter creates a new OTLP HTTP exporter.
func NewHTTPOTLPExporter(cfg *config.OTLPConfig, serviceName, serviceVersion, deploymentEnv string, logger *zap.Logger) (*HTTPOTLPExporter, error) {
	scheme := "https"
	if cfg.Insecure {
		scheme = "http"
	}

	endpoint := fmt.Sprintf("%s://%s", scheme, cfg.Endpoint)

	compression := cfg.Compression
	if compression == "" {
		compression = "gzip"
	}

	return &HTTPOTLPExporter{
		logger:         logger,
		serviceName:    serviceName,
		serviceVersion: serviceVersion,
		deploymentEnv:  deploymentEnv,
		endpoint:       endpoint,
		compression:    compression,
		headers:        cfg.Headers,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// resourceForService returns OTEL resource for a specific service (shared logic with gRPC exporter).
func (e *HTTPOTLPExporter) resourceForService(serviceName string, pid uint32) *OTLPResource {
	return &OTLPResource{
		serviceName:    serviceName,
		serviceVersion: e.serviceVersion,
		deploymentEnv:  e.deploymentEnv,
		fallbackName:   e.serviceName,
		pid:            pid,
	}
}

// ExportSpans sends spans via OTLP HTTP.
func (e *HTTPOTLPExporter) ExportSpans(ctx context.Context, spans []*traces.Span) error {
	if len(spans) == 0 {
		return nil
	}

	// Use a temporary gRPC-style converter for span conversion
	conv := &OTLPExporter{
		serviceName:    e.serviceName,
		serviceVersion: e.serviceVersion,
		deploymentEnv:  e.deploymentEnv,
	}

	type svcKey struct {
		name string
		pid  uint32
	}
	grouped := make(map[svcKey][]*tracepb.Span)
	for _, s := range spans {
		ps, err := conv.convertSpan(s)
		if err != nil {
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
			Resource: conv.resourceForService(key.name, key.pid),
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

	return e.post(ctx, "/v1/traces", req)
}

// ExportLogs sends log records via OTLP HTTP, grouped by service.
func (e *HTTPOTLPExporter) ExportLogs(ctx context.Context, logs []*LogRecord) error {
	if len(logs) == 0 {
		return nil
	}

	conv := &OTLPExporter{
		serviceName:    e.serviceName,
		serviceVersion: e.serviceVersion,
		deploymentEnv:  e.deploymentEnv,
	}

	type svcKey struct {
		name string
		pid  int
	}
	grouped := make(map[svcKey][]*logspb.LogRecord)
	for _, l := range logs {
		pl := conv.convertLogRecord(l)
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
			Resource: conv.resourceForService(key.name, uint32(key.pid)),
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

	return e.post(ctx, "/v1/logs", req)
}

// ExportMetrics sends metrics via OTLP HTTP, grouped by service.
func (e *HTTPOTLPExporter) ExportMetrics(ctx context.Context, metrics []*Metric) error {
	if len(metrics) == 0 {
		return nil
	}

	conv := &OTLPExporter{
		serviceName:    e.serviceName,
		serviceVersion: e.serviceVersion,
		deploymentEnv:  e.deploymentEnv,
	}

	grouped := make(map[string][]*metricspb.Metric)
	for _, m := range metrics {
		pm := conv.convertMetric(m)
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
			Resource: conv.resourceForService(svcName, uint32(os.Getpid())),
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

	return e.post(ctx, "/v1/metrics", req)
}

// post sends a protobuf-encoded request to the OTLP HTTP endpoint.
func (e *HTTPOTLPExporter) post(ctx context.Context, path string, msg proto.Message) error {
	data, err := proto.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal protobuf: %w", err)
	}

	var body io.Reader
	body = bytes.NewReader(data)
	contentEncoding := ""

	if e.compression == "gzip" {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(data); err != nil {
			return fmt.Errorf("gzip compress: %w", err)
		}
		if err := gz.Close(); err != nil {
			return fmt.Errorf("gzip close: %w", err)
		}
		body = &buf
		contentEncoding = "gzip"
	}

	url := e.endpoint + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	if contentEncoding != "" {
		req.Header.Set("Content-Encoding", contentEncoding)
	}
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("http post %s: %w", path, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("OTLP HTTP %s returned %d", path, resp.StatusCode)
}

// Shutdown closes the HTTP client.
func (e *HTTPOTLPExporter) Shutdown(ctx context.Context) error {
	e.client.CloseIdleConnections()
	return nil
}

// OTLPResource is a helper for building resource attributes (used by HTTP exporter).
type OTLPResource struct {
	serviceName    string
	serviceVersion string
	deploymentEnv  string
	fallbackName   string
	pid            uint32
}
