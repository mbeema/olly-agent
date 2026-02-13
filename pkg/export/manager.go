// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package export

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/profiling"
	"github.com/mbeema/olly/pkg/traces"
	"go.uber.org/zap"
)

// LogRecord represents a log entry for export.
type LogRecord struct {
	Timestamp      time.Time
	ObservedTime   time.Time // R3.2: When the collector received the log
	Body           string
	Level          string
	SeverityNumber int32 // R3.1: OTEL SeverityNumber (1-24)
	Attributes     map[string]interface{}
	Resource       map[string]string
	PID            int
	TID            int
	TraceID        string
	SpanID         string
	ServiceName    string
	Source         string
	FilePath       string
}

// Metric represents a metric data point for export.
type Metric struct {
	Name        string
	Description string
	Unit        string
	Type        MetricType
	Value       float64
	Timestamp   time.Time
	Labels      map[string]string
	Histogram   *HistogramValue
	ServiceName string // Service that produced this metric
}

// MetricType identifies the kind of metric.
type MetricType int

const (
	MetricGauge MetricType = iota
	MetricCounter
	MetricHistogram
)

// HistogramValue holds histogram data.
type HistogramValue struct {
	Count   uint64
	Sum     float64
	Buckets []HistogramBucket
}

// HistogramBucket is a single histogram bucket.
type HistogramBucket struct {
	UpperBound float64
	Count      uint64
}

// Exporter is the interface for telemetry exporters.
type Exporter interface {
	ExportSpans(ctx context.Context, spans []*traces.Span) error
	ExportLogs(ctx context.Context, logs []*LogRecord) error
	ExportMetrics(ctx context.Context, metrics []*Metric) error
	Shutdown(ctx context.Context) error
}

const (
	defaultBatchSize     = 1000
	defaultFlushInterval = 5 * time.Second
	defaultChannelSize   = 10000

	// H1 fix: retry constants
	maxRetries     = 3
	initialBackoff = 100 * time.Millisecond
	maxBackoff     = 5 * time.Second
	backoffFactor  = 2.0
)

// Manager coordinates batching and export of all telemetry signals.
type Manager struct {
	logger    *zap.Logger
	exporters []Exporter

	spanCh    chan *traces.Span
	logCh     chan *LogRecord
	metricCh  chan *Metric
	profileCh chan *profiling.Profile

	spanCount    atomic.Int64
	logCount     atomic.Int64
	metricCount  atomic.Int64
	profileCount atomic.Int64
	dropCount    atomic.Int64

	batchSize     int
	flushInterval time.Duration

	pyroscope      *PyroscopeExporter
	circuitBreaker *CircuitBreaker

	wg     sync.WaitGroup
	stopCh chan struct{}
}

// ManagerConfig holds the configuration needed to create a Manager.
type ManagerConfig struct {
	Exporters      *config.ExportersConfig
	ServiceName    string
	ServiceVersion string
	DeploymentEnv  string
	PyroscopeCfg   *config.PyroscopeConfig
}

// NewManager creates a new export manager from configuration.
func NewManager(cfg *config.ExportersConfig, serviceName string, logger *zap.Logger, pyroscopeCfg ...*config.PyroscopeConfig) (*Manager, error) {
	mc := &ManagerConfig{
		Exporters:   cfg,
		ServiceName: serviceName,
	}
	if len(pyroscopeCfg) > 0 {
		mc.PyroscopeCfg = pyroscopeCfg[0]
	}
	return NewManagerFromConfig(mc, logger)
}

// NewManagerFromConfig creates a new export manager with full config support.
func NewManagerFromConfig(mc *ManagerConfig, logger *zap.Logger) (*Manager, error) {
	m := &Manager{
		logger:         logger,
		spanCh:         make(chan *traces.Span, defaultChannelSize),
		logCh:          make(chan *LogRecord, defaultChannelSize),
		metricCh:       make(chan *Metric, defaultChannelSize),
		profileCh:      make(chan *profiling.Profile, defaultChannelSize),
		batchSize:      defaultBatchSize,
		flushInterval:  defaultFlushInterval,
		circuitBreaker: NewCircuitBreaker(5, 30*time.Second),
		stopCh:         make(chan struct{}),
	}

	cfg := mc.Exporters

	// Initialize exporters
	if cfg.OTLP.Enabled {
		var exp Exporter
		var err error
		if cfg.OTLP.Protocol == "http" {
			exp, err = NewHTTPOTLPExporter(&cfg.OTLP, mc.ServiceName, mc.ServiceVersion, mc.DeploymentEnv, logger)
		} else {
			exp, err = NewOTLPExporter(&cfg.OTLP, mc.ServiceName, mc.ServiceVersion, mc.DeploymentEnv, logger)
		}
		if err != nil {
			logger.Warn("failed to create OTLP exporter", zap.Error(err))
		} else {
			m.exporters = append(m.exporters, exp)
		}
	}

	if cfg.Stdout.Enabled {
		m.exporters = append(m.exporters, NewStdoutExporter(cfg.Stdout.Format, logger))
	}

	// Initialize Pyroscope exporter if configured
	if mc.PyroscopeCfg != nil && mc.PyroscopeCfg.Enabled {
		m.pyroscope = NewPyroscopeExporter(mc.PyroscopeCfg, logger)
		logger.Info("pyroscope exporter enabled", zap.String("endpoint", mc.PyroscopeCfg.Endpoint))
	}

	return m, nil
}

// Start begins the batch export goroutines.
func (m *Manager) Start(ctx context.Context) error {
	m.wg.Add(3)
	go m.processSpans(ctx)
	go m.processLogs(ctx)
	go m.processMetrics(ctx)

	if m.pyroscope != nil {
		m.wg.Add(1)
		go m.processProfiles(ctx)
	}

	m.logger.Info("export manager started",
		zap.Int("exporters", len(m.exporters)),
		zap.Int("batch_size", m.batchSize),
		zap.Duration("flush_interval", m.flushInterval),
		zap.Bool("pyroscope", m.pyroscope != nil),
	)

	return nil
}

// Stop flushes remaining data and shuts down exporters.
func (m *Manager) Stop() error {
	close(m.stopCh)
	m.wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, exp := range m.exporters {
		if err := exp.Shutdown(ctx); err != nil {
			m.logger.Error("exporter shutdown error", zap.Error(err))
		}
	}

	if m.pyroscope != nil {
		if err := m.pyroscope.Shutdown(ctx); err != nil {
			m.logger.Error("pyroscope shutdown error", zap.Error(err))
		}
	}

	m.logger.Info("export manager stopped",
		zap.Int64("spans_exported", m.spanCount.Load()),
		zap.Int64("logs_exported", m.logCount.Load()),
		zap.Int64("metrics_exported", m.metricCount.Load()),
		zap.Int64("profiles_exported", m.profileCount.Load()),
		zap.Int64("dropped", m.dropCount.Load()),
	)

	return nil
}

// ExportSpan queues a span for export.
func (m *Manager) ExportSpan(span *traces.Span) {
	select {
	case m.spanCh <- span:
	default:
		m.dropCount.Add(1)
		m.logger.Warn("span channel full, dropping span")
	}
}

// ExportLog queues a log record for export.
func (m *Manager) ExportLog(log *LogRecord) {
	select {
	case m.logCh <- log:
	default:
		m.dropCount.Add(1)
		m.logger.Warn("log channel full, dropping log")
	}
}

// ExportMetric queues a metric for export.
func (m *Manager) ExportMetric(metric *Metric) {
	select {
	case m.metricCh <- metric:
	default:
		m.dropCount.Add(1)
		m.logger.Warn("metric channel full, dropping metric")
	}
}

// ExportProfile queues a profile for export.
func (m *Manager) ExportProfile(p *profiling.Profile) {
	select {
	case m.profileCh <- p:
	default:
		m.dropCount.Add(1)
		m.logger.Warn("profile channel full, dropping profile")
	}
}

func (m *Manager) processSpans(ctx context.Context) {
	defer m.wg.Done()

	batch := make([]*traces.Span, 0, m.batchSize)
	ticker := time.NewTicker(m.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case span := <-m.spanCh:
			batch = append(batch, span)
			if len(batch) >= m.batchSize {
				m.flushSpans(ctx, batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				m.flushSpans(ctx, batch)
				batch = batch[:0]
			}

		case <-m.stopCh:
			// Drain remaining
			for {
				select {
				case span := <-m.spanCh:
					batch = append(batch, span)
				default:
					if len(batch) > 0 {
						m.flushSpans(ctx, batch)
					}
					return
				}
			}

		case <-ctx.Done():
			// Drain remaining spans before exit
			for {
				select {
				case span := <-m.spanCh:
					batch = append(batch, span)
				default:
					if len(batch) > 0 {
						m.flushSpans(context.Background(), batch)
					}
					return
				}
			}
		}
	}
}

func (m *Manager) processLogs(ctx context.Context) {
	defer m.wg.Done()

	batch := make([]*LogRecord, 0, m.batchSize)
	ticker := time.NewTicker(m.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case log := <-m.logCh:
			batch = append(batch, log)
			if len(batch) >= m.batchSize {
				m.flushLogs(ctx, batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				m.flushLogs(ctx, batch)
				batch = batch[:0]
			}

		case <-m.stopCh:
			for {
				select {
				case log := <-m.logCh:
					batch = append(batch, log)
				default:
					if len(batch) > 0 {
						m.flushLogs(ctx, batch)
					}
					return
				}
			}

		case <-ctx.Done():
			for {
				select {
				case log := <-m.logCh:
					batch = append(batch, log)
				default:
					if len(batch) > 0 {
						m.flushLogs(context.Background(), batch)
					}
					return
				}
			}
		}
	}
}

func (m *Manager) processMetrics(ctx context.Context) {
	defer m.wg.Done()

	batch := make([]*Metric, 0, m.batchSize)
	ticker := time.NewTicker(m.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case metric := <-m.metricCh:
			batch = append(batch, metric)
			if len(batch) >= m.batchSize {
				m.flushMetrics(ctx, batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				m.flushMetrics(ctx, batch)
				batch = batch[:0]
			}

		case <-m.stopCh:
			for {
				select {
				case metric := <-m.metricCh:
					batch = append(batch, metric)
				default:
					if len(batch) > 0 {
						m.flushMetrics(ctx, batch)
					}
					return
				}
			}

		case <-ctx.Done():
			for {
				select {
				case metric := <-m.metricCh:
					batch = append(batch, metric)
				default:
					if len(batch) > 0 {
						m.flushMetrics(context.Background(), batch)
					}
					return
				}
			}
		}
	}
}

func (m *Manager) processProfiles(ctx context.Context) {
	defer m.wg.Done()

	batch := make([]*profiling.Profile, 0, 16)
	ticker := time.NewTicker(m.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case p := <-m.profileCh:
			batch = append(batch, p)
			if len(batch) >= 16 {
				m.flushProfiles(ctx, batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			if len(batch) > 0 {
				m.flushProfiles(ctx, batch)
				batch = batch[:0]
			}

		case <-m.stopCh:
			for {
				select {
				case p := <-m.profileCh:
					batch = append(batch, p)
				default:
					if len(batch) > 0 {
						m.flushProfiles(ctx, batch)
					}
					return
				}
			}

		case <-ctx.Done():
			for {
				select {
				case p := <-m.profileCh:
					batch = append(batch, p)
				default:
					if len(batch) > 0 {
						m.flushProfiles(context.Background(), batch)
					}
					return
				}
			}
		}
	}
}

func (m *Manager) flushProfiles(ctx context.Context, profiles []*profiling.Profile) {
	if m.pyroscope == nil {
		return
	}
	for _, p := range profiles {
		if err := m.pyroscope.ExportProfile(ctx, p); err != nil {
			m.logger.Error("pyroscope export error",
				zap.String("service", p.ServiceName),
				zap.Error(err),
			)
		}
	}
	m.profileCount.Add(int64(len(profiles)))
}

// H1 fix: flushSpans with exponential backoff retry.
func (m *Manager) flushSpans(ctx context.Context, spans []*traces.Span) {
	for _, exp := range m.exporters {
		m.retryExport(ctx, "spans", func(expCtx context.Context) error {
			return exp.ExportSpans(expCtx, spans)
		})
	}
	m.spanCount.Add(int64(len(spans)))
}

func (m *Manager) flushLogs(ctx context.Context, logs []*LogRecord) {
	for _, exp := range m.exporters {
		m.retryExport(ctx, "logs", func(expCtx context.Context) error {
			return exp.ExportLogs(expCtx, logs)
		})
	}
	m.logCount.Add(int64(len(logs)))
}

func (m *Manager) flushMetrics(ctx context.Context, metrics []*Metric) {
	for _, exp := range m.exporters {
		m.retryExport(ctx, "metrics", func(expCtx context.Context) error {
			return exp.ExportMetrics(expCtx, metrics)
		})
	}
	m.metricCount.Add(int64(len(metrics)))
}

// retryExport attempts an export with exponential backoff and circuit breaker.
func (m *Manager) retryExport(ctx context.Context, signal string, exportFn func(context.Context) error) {
	if !m.circuitBreaker.Allow() {
		m.dropCount.Add(1)
		m.logger.Debug("circuit breaker open, dropping export",
			zap.String("signal", signal),
		)
		return
	}

	backoff := initialBackoff

	for attempt := 0; attempt <= maxRetries; attempt++ {
		exportCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := exportFn(exportCtx)
		cancel()

		if err == nil {
			m.circuitBreaker.RecordSuccess()
			return
		}

		m.circuitBreaker.RecordFailure()

		if attempt == maxRetries {
			m.logger.Error("export failed after retries",
				zap.String("signal", signal),
				zap.Int("attempts", attempt+1),
				zap.Error(err),
			)
			m.dropCount.Add(1)
			return
		}

		m.logger.Warn("export failed, retrying",
			zap.String("signal", signal),
			zap.Int("attempt", attempt+1),
			zap.Duration("backoff", backoff),
			zap.Error(err),
		)

		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return
		}

		// Exponential backoff with cap
		backoff = time.Duration(math.Min(
			float64(backoff)*backoffFactor,
			float64(maxBackoff),
		))
	}
}

// Stats returns current export statistics.
func (m *Manager) Stats() (spans, logs, metrics, profiles int64) {
	return m.spanCount.Load(), m.logCount.Load(), m.metricCount.Load(), m.profileCount.Load()
}

// DropCount returns the number of dropped telemetry items.
func (m *Manager) DropCount() int64 {
	return m.dropCount.Load()
}

// ChannelDepths returns current channel fill levels for monitoring.
func (m *Manager) ChannelDepths() (spans, logs, metrics int) {
	return len(m.spanCh), len(m.logCh), len(m.metricCh)
}
