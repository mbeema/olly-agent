package export

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mbeema/olly/pkg/traces"
	"go.uber.org/zap"
)

// StdoutExporter prints telemetry to stdout for debugging.
type StdoutExporter struct {
	format string // "text" or "json"
	logger *zap.Logger
}

// NewStdoutExporter creates a new stdout exporter.
func NewStdoutExporter(format string, logger *zap.Logger) *StdoutExporter {
	if format == "" {
		format = "text"
	}
	return &StdoutExporter{
		format: format,
		logger: logger,
	}
}

// ExportSpans prints spans to stdout.
func (e *StdoutExporter) ExportSpans(ctx context.Context, spans []*traces.Span) error {
	for _, s := range spans {
		if e.format == "json" {
			e.printJSON("span", map[string]interface{}{
				"trace_id":    s.TraceID,
				"span_id":     s.SpanID,
				"parent_id":   s.ParentSpanID,
				"name":        s.Name,
				"kind":        s.Kind.String(),
				"start":       s.StartTime.Format(time.RFC3339Nano),
				"end":         s.EndTime.Format(time.RFC3339Nano),
				"duration_ms": s.Duration.Milliseconds(),
				"status":      s.Status,
				"service":     s.ServiceName,
				"protocol":    s.Protocol,
				"remote":      fmt.Sprintf("%s:%d", s.RemoteAddr, s.RemotePort),
				"attributes":  s.Attributes,
			})
		} else {
			status := "OK"
			if s.Status == traces.StatusError {
				status = "ERR"
			}
			fmt.Fprintf(os.Stdout,
				"[SPAN] trace=%s span=%s name=%-40s %s %6dms %s:%d pid=%d %s\n",
				s.TraceID[:16], s.SpanID[:8], s.Name,
				status, s.Duration.Milliseconds(),
				s.RemoteAddr, s.RemotePort, s.PID,
				formatAttrs(s.Attributes),
			)
		}
	}
	return nil
}

// ExportLogs prints log records to stdout.
func (e *StdoutExporter) ExportLogs(ctx context.Context, logs []*LogRecord) error {
	for _, l := range logs {
		if e.format == "json" {
			e.printJSON("log", map[string]interface{}{
				"timestamp":  l.Timestamp.Format(time.RFC3339Nano),
				"level":      l.Level,
				"body":       l.Body,
				"trace_id":   l.TraceID,
				"span_id":    l.SpanID,
				"service":    l.ServiceName,
				"pid":        l.PID,
				"source":     l.Source,
				"attributes": l.Attributes,
			})
		} else {
			traceInfo := ""
			if l.TraceID != "" {
				traceInfo = fmt.Sprintf(" trace=%s span=%s", l.TraceID[:min(len(l.TraceID), 16)], l.SpanID[:min(len(l.SpanID), 8)])
			}
			body := l.Body
			if len(body) > 200 {
				body = body[:200] + "..."
			}
			fmt.Fprintf(os.Stdout,
				"[LOG]  %-5s pid=%d%s %s\n",
				l.Level, l.PID, traceInfo, body,
			)
		}
	}
	return nil
}

// ExportMetrics prints metrics to stdout.
func (e *StdoutExporter) ExportMetrics(ctx context.Context, metrics []*Metric) error {
	for _, m := range metrics {
		if e.format == "json" {
			e.printJSON("metric", map[string]interface{}{
				"name":      m.Name,
				"type":      metricTypeName(m.Type),
				"value":     m.Value,
				"unit":      m.Unit,
				"timestamp": m.Timestamp.Format(time.RFC3339Nano),
				"labels":    m.Labels,
			})
		} else {
			fmt.Fprintf(os.Stdout,
				"[METRIC] %-40s %s %.4f %s %s\n",
				m.Name, metricTypeName(m.Type), m.Value, m.Unit,
				formatLabels(m.Labels),
			)
		}
	}
	return nil
}

// Shutdown is a no-op for stdout.
func (e *StdoutExporter) Shutdown(ctx context.Context) error {
	return nil
}

func (e *StdoutExporter) printJSON(typ string, data map[string]interface{}) {
	data["_type"] = typ
	b, _ := json.Marshal(data)
	fmt.Fprintf(os.Stdout, "%s\n", b)
}

func formatAttrs(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	var parts []string
	for k, v := range attrs {
		if len(parts) >= 5 {
			parts = append(parts, "...")
			break
		}
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, " ")
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	var parts []string
	for k, v := range labels {
		parts = append(parts, fmt.Sprintf("%s=%q", k, v))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func metricTypeName(t MetricType) string {
	switch t {
	case MetricGauge:
		return "gauge"
	case MetricCounter:
		return "counter"
	case MetricHistogram:
		return "histogram"
	default:
		return "unknown"
	}
}
