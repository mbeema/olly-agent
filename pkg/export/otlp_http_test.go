// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package export

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/traces"
	"google.golang.org/protobuf/proto"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
)

func newTestHTTPExporter(t *testing.T, handler http.HandlerFunc) (*HTTPOTLPExporter, *httptest.Server) {
	ts := httptest.NewServer(handler)
	cfg := &config.OTLPConfig{
		Endpoint:    strings.TrimPrefix(ts.URL, "http://"),
		Protocol:    "http",
		Compression: "gzip",
		Insecure:    true,
	}
	exp, err := NewHTTPOTLPExporter(cfg, "test-service", "1.0.0", "test", nil)
	if err != nil {
		t.Fatalf("NewHTTPOTLPExporter: %v", err)
	}
	return exp, ts
}

func TestHTTPExporterSpans(t *testing.T) {
	var receivedPath string
	var receivedContentType string
	var receivedEncoding string
	var receivedBody []byte

	exp, ts := newTestHTTPExporter(t, func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		receivedContentType = r.Header.Get("Content-Type")
		receivedEncoding = r.Header.Get("Content-Encoding")

		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Fatalf("gzip reader: %v", err)
			}
			defer gz.Close()
			reader = gz
		}
		receivedBody, _ = io.ReadAll(reader)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	now := time.Now()
	spans := []*traces.Span{
		{
			TraceID:     "0123456789abcdef0123456789abcdef",
			SpanID:      "0123456789abcdef",
			Name:        "GET /api/test",
			Kind:        traces.SpanKindServer,
			StartTime:   now,
			EndTime:     now.Add(100 * time.Millisecond),
			Duration:    100 * time.Millisecond,
			ServiceName: "test-service",
			PID:         1234,
			Attributes:  map[string]string{"http.method": "GET"},
		},
	}

	err := exp.ExportSpans(context.Background(), spans)
	if err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}

	if receivedPath != "/v1/traces" {
		t.Errorf("expected path /v1/traces, got %s", receivedPath)
	}
	if receivedContentType != "application/x-protobuf" {
		t.Errorf("expected content-type application/x-protobuf, got %s", receivedContentType)
	}
	if receivedEncoding != "gzip" {
		t.Errorf("expected content-encoding gzip, got %s", receivedEncoding)
	}

	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(receivedBody, &req); err != nil {
		t.Fatalf("unmarshal trace request: %v", err)
	}
	if len(req.ResourceSpans) == 0 {
		t.Fatal("expected at least 1 ResourceSpans")
	}
}

func TestHTTPExporterLogs(t *testing.T) {
	var receivedPath string
	var receivedBody []byte

	exp, ts := newTestHTTPExporter(t, func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		gz, _ := gzip.NewReader(r.Body)
		defer gz.Close()
		receivedBody, _ = io.ReadAll(gz)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	logs := []*LogRecord{
		{
			Timestamp:   time.Now(),
			Body:        "test log message",
			Level:       "INFO",
			Attributes:  map[string]interface{}{},
			ServiceName: "svc-a",
			PID:         1000,
		},
		{
			Timestamp:   time.Now(),
			Body:        "another log",
			Level:       "ERROR",
			Attributes:  map[string]interface{}{},
			ServiceName: "svc-b",
			PID:         2000,
		},
	}

	err := exp.ExportLogs(context.Background(), logs)
	if err != nil {
		t.Fatalf("ExportLogs: %v", err)
	}

	if receivedPath != "/v1/logs" {
		t.Errorf("expected path /v1/logs, got %s", receivedPath)
	}

	var req collogspb.ExportLogsServiceRequest
	if err := proto.Unmarshal(receivedBody, &req); err != nil {
		t.Fatalf("unmarshal logs request: %v", err)
	}
	if len(req.ResourceLogs) < 2 {
		t.Errorf("expected 2 ResourceLogs for 2 services, got %d", len(req.ResourceLogs))
	}
}

func TestHTTPExporterMetrics(t *testing.T) {
	var receivedPath string
	var receivedBody []byte

	exp, ts := newTestHTTPExporter(t, func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		gz, _ := gzip.NewReader(r.Body)
		defer gz.Close()
		receivedBody, _ = io.ReadAll(gz)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	metrics := []*Metric{
		{
			Name:        "test.gauge",
			Type:        MetricGauge,
			Value:       42.0,
			Timestamp:   time.Now(),
			Labels:      map[string]string{},
			ServiceName: "svc-a",
		},
	}

	err := exp.ExportMetrics(context.Background(), metrics)
	if err != nil {
		t.Fatalf("ExportMetrics: %v", err)
	}

	if receivedPath != "/v1/metrics" {
		t.Errorf("expected path /v1/metrics, got %s", receivedPath)
	}

	var req colmetricspb.ExportMetricsServiceRequest
	if err := proto.Unmarshal(receivedBody, &req); err != nil {
		t.Fatalf("unmarshal metrics request: %v", err)
	}
	if len(req.ResourceMetrics) == 0 {
		t.Fatal("expected at least 1 ResourceMetrics")
	}
}

func TestHTTPExporterNoCompression(t *testing.T) {
	var receivedEncoding string

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedEncoding = r.Header.Get("Content-Encoding")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := &config.OTLPConfig{
		Endpoint:    strings.TrimPrefix(ts.URL, "http://"),
		Protocol:    "http",
		Compression: "none",
		Insecure:    true,
	}
	exp, err := NewHTTPOTLPExporter(cfg, "test-service", "", "", nil)
	if err != nil {
		t.Fatalf("NewHTTPOTLPExporter: %v", err)
	}

	err = exp.ExportSpans(context.Background(), []*traces.Span{
		{
			TraceID:    "0123456789abcdef0123456789abcdef",
			SpanID:     "0123456789abcdef",
			Name:       "test",
			Kind:       traces.SpanKindServer,
			StartTime:  time.Now(),
			EndTime:    time.Now(),
			Attributes: map[string]string{},
		},
	})
	if err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}

	if receivedEncoding != "" {
		t.Errorf("expected no Content-Encoding header, got %q", receivedEncoding)
	}
}

func TestHTTPExporterPerServiceSpanGrouping(t *testing.T) {
	var receivedBody []byte

	exp, ts := newTestHTTPExporter(t, func(w http.ResponseWriter, r *http.Request) {
		gz, _ := gzip.NewReader(r.Body)
		defer gz.Close()
		receivedBody, _ = io.ReadAll(gz)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	now := time.Now()
	spans := []*traces.Span{
		{
			TraceID:     "0123456789abcdef0123456789abcdef",
			SpanID:      "0123456789abcdef",
			Name:        "op-a",
			Kind:        traces.SpanKindServer,
			StartTime:   now,
			EndTime:     now.Add(10 * time.Millisecond),
			ServiceName: "service-a",
			PID:         100,
			Attributes:  map[string]string{},
		},
		{
			TraceID:     "0123456789abcdef0123456789abcdef",
			SpanID:      "abcdef0123456789",
			Name:        "op-b",
			Kind:        traces.SpanKindClient,
			StartTime:   now,
			EndTime:     now.Add(20 * time.Millisecond),
			ServiceName: "service-b",
			PID:         200,
			Attributes:  map[string]string{},
		},
	}

	err := exp.ExportSpans(context.Background(), spans)
	if err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}

	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(receivedBody, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(req.ResourceSpans) < 2 {
		t.Errorf("expected 2 ResourceSpans for 2 services, got %d", len(req.ResourceSpans))
	}
}

func TestHTTPExporterResourceAttributes(t *testing.T) {
	var receivedBody []byte

	exp, ts := newTestHTTPExporter(t, func(w http.ResponseWriter, r *http.Request) {
		gz, _ := gzip.NewReader(r.Body)
		defer gz.Close()
		receivedBody, _ = io.ReadAll(gz)
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	now := time.Now()
	spans := []*traces.Span{
		{
			TraceID:     "0123456789abcdef0123456789abcdef",
			SpanID:      "0123456789abcdef",
			Name:        "test",
			Kind:        traces.SpanKindServer,
			StartTime:   now,
			EndTime:     now.Add(10 * time.Millisecond),
			ServiceName: "my-app",
			PID:         1234,
			Attributes:  map[string]string{},
		},
	}

	err := exp.ExportSpans(context.Background(), spans)
	if err != nil {
		t.Fatalf("ExportSpans: %v", err)
	}

	var req coltracepb.ExportTraceServiceRequest
	if err := proto.Unmarshal(receivedBody, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(req.ResourceSpans) == 0 {
		t.Fatal("expected ResourceSpans")
	}

	foundVersion := false
	foundEnv := false
	for _, attr := range req.ResourceSpans[0].Resource.Attributes {
		if attr.Key == "service.version" && attr.Value.GetStringValue() == "1.0.0" {
			foundVersion = true
		}
		if attr.Key == "deployment.environment" && attr.Value.GetStringValue() == "test" {
			foundEnv = true
		}
	}
	if !foundVersion {
		t.Error("service.version attribute missing or incorrect")
	}
	if !foundEnv {
		t.Error("deployment.environment attribute missing or incorrect")
	}
}

func TestHTTPExporterShutdown(t *testing.T) {
	exp, ts := newTestHTTPExporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer ts.Close()

	err := exp.Shutdown(context.Background())
	if err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestHTTPExporterEmptySpans(t *testing.T) {
	exp, ts := newTestHTTPExporter(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not be called for empty spans")
	})
	defer ts.Close()

	err := exp.ExportSpans(context.Background(), nil)
	if err != nil {
		t.Errorf("ExportSpans with nil: %v", err)
	}
	err = exp.ExportSpans(context.Background(), []*traces.Span{})
	if err != nil {
		t.Errorf("ExportSpans with empty: %v", err)
	}
}

func TestHTTPExporterServerError(t *testing.T) {
	exp, ts := newTestHTTPExporter(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer ts.Close()

	err := exp.ExportSpans(context.Background(), []*traces.Span{
		{
			TraceID:    "0123456789abcdef0123456789abcdef",
			SpanID:     "0123456789abcdef",
			Name:       "test",
			Kind:       traces.SpanKindServer,
			StartTime:  time.Now(),
			EndTime:    time.Now(),
			Attributes: map[string]string{},
		},
	})
	if err == nil {
		t.Error("expected error for 500 response")
	}
}
