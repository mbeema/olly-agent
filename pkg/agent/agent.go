package agent

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/conntrack"
	"github.com/mbeema/olly/pkg/correlation"
	"github.com/mbeema/olly/pkg/discovery"
	"github.com/mbeema/olly/pkg/export"
	"github.com/mbeema/olly/pkg/hook"
	"github.com/mbeema/olly/pkg/logs"
	"github.com/mbeema/olly/pkg/metrics"
	rmetrics "github.com/mbeema/olly/pkg/metrics"
	"github.com/mbeema/olly/pkg/protocol"
	"github.com/mbeema/olly/pkg/reassembly"
	"github.com/mbeema/olly/pkg/servicemap"
	"github.com/mbeema/olly/pkg/traces"
	"go.uber.org/zap"
)

// Agent is the main orchestrator that wires all subsystems together.
// C9 fix: All inter-component communication goes through buffered channels
// to avoid holding locks across subsystem boundaries.
// C10 fix: Config is stored as atomic pointer, safe for concurrent access.
type Agent struct {
	cfg    atomic.Pointer[config.Config]
	logger *zap.Logger

	hookMgr        *hook.Manager
	connTracker    *conntrack.Tracker
	reassembler    *reassembly.Reassembler
	traceProc      *traces.Processor
	correlation    *correlation.Engine
	logCollector   *logs.Collector
	metricsColl    *metrics.Collector
	requestMetrics *rmetrics.RequestMetrics
	exporter       *export.Manager
	discoverer     *discovery.Discoverer
	serviceMap     *servicemap.Generator

	// Decoupled channels (C9 fix) - prevent callback deadlocks
	pairCh chan *reassembly.RequestPair
	logCh  chan *logs.LogRecord
	spanCh chan *traces.Span

	// Thread-local trace context for intra-process parent-child linking.
	// Maps PID+TID → trace context when an inbound HTTP request is active.
	threadCtx sync.Map // key: uint64(pid)<<32|uint64(tid), value: *threadTraceCtx

	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	metricsCancel context.CancelFunc // per-subsystem cancel for request metrics loop
	wg            sync.WaitGroup
}

// threadTraceCtx holds trace context for an active inbound request on a thread.
type threadTraceCtx struct {
	TraceID  string
	SpanID   string
	Created  time.Time
}

// New creates a new agent from configuration.
func New(cfg *config.Config, logger *zap.Logger) (*Agent, error) {
	a := &Agent{
		logger: logger,
		pairCh: make(chan *reassembly.RequestPair, 10000),
		logCh:  make(chan *logs.LogRecord, 10000),
		spanCh: make(chan *traces.Span, 10000),
	}
	a.cfg.Store(cfg)

	// Initialize connection tracker
	a.connTracker = conntrack.NewTracker()

	// Initialize reassembler
	a.reassembler = reassembly.NewReassembler(logger)

	// Initialize trace processor
	a.traceProc = traces.NewProcessor(logger)

	// Initialize correlation engine
	a.correlation = correlation.NewEngine(cfg.Correlation.Window, logger)

	// Initialize export manager
	serviceName := cfg.ServiceName
	if serviceName == "auto" || serviceName == "" {
		serviceName = "olly-agent"
	}

	exporter, err := export.NewManager(&cfg.Exporters, serviceName, logger)
	if err != nil {
		return nil, fmt.Errorf("create exporter: %w", err)
	}
	a.exporter = exporter

	// Initialize log collector
	if cfg.Logs.Enabled {
		a.logCollector = logs.NewCollector(&cfg.Logs, logger)
	}

	// Initialize metrics collector
	if cfg.Metrics.Enabled {
		a.metricsColl = metrics.NewCollector(&cfg.Metrics, logger)
		a.requestMetrics = rmetrics.NewRequestMetrics(cfg.Metrics.Request.Buckets)
	}

	// Initialize discovery
	if cfg.Discovery.Enabled {
		a.discoverer = discovery.NewDiscoverer(cfg.Discovery.EnvVars, cfg.Discovery.PortMappings, logger)
	}

	// Initialize service map
	a.serviceMap = servicemap.NewGenerator(logger)

	return a, nil
}

// Start begins all agent subsystems and wires them together.
func (a *Agent) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	a.ctx = ctx
	a.cancel = cancel

	cfg := a.cfg.Load()

	// Wire callbacks: Hook → ConnTracker → Reassembler
	// These callbacks are lightweight - they only append to buffers or send to channels.
	callbacks := hook.Callbacks{
		OnConnect: func(pid, tid uint32, fd int32, remoteAddr uint32, remotePort uint16, ts uint64) {
			a.connTracker.Register(pid, fd, remoteAddr, remotePort)

			// Update service map
			if a.discoverer != nil && a.serviceMap != nil {
				srcService := a.discoverer.GetServiceName(pid)
				dstService := a.discoverer.GetServiceNameByPort(remotePort)
				a.serviceMap.RecordConnection(srcService, dstService, remotePort)
			}
		},

		// R2.3: Track inbound connections from accept() for SERVER span kind
		OnAccept: func(pid, tid uint32, fd int32, remoteAddr uint32, remotePort uint16, ts uint64) {
			a.connTracker.RegisterInbound(pid, fd, remoteAddr, remotePort)
		},

		OnDataOut: func(pid, tid uint32, fd int32, data []byte, ts uint64) {
			conn := a.connTracker.Lookup(pid, fd)
			if conn == nil {
				return
			}
			a.connTracker.AddBytesSent(pid, fd, uint64(len(data)))

			remoteAddr := conn.RemoteAddrStr()
			remotePort := conn.RemotePort
			// For inbound (server) connections, outgoing data is the response.
			// Swap to keep sendBuf=request, recvBuf=response in the reassembler.
			if conn.Direction == conntrack.ConnInbound {
				a.reassembler.AppendRecv(pid, tid, fd, data, remoteAddr, remotePort, false)
				a.reassembler.SetDirection(pid, fd, 1) // 1=inbound
			} else {
				a.reassembler.AppendSend(pid, tid, fd, data, remoteAddr, remotePort, false)
			}
		},

		OnDataIn: func(pid, tid uint32, fd int32, data []byte, ts uint64) {
			conn := a.connTracker.Lookup(pid, fd)
			if conn == nil {
				return
			}
			a.connTracker.AddBytesRecv(pid, fd, uint64(len(data)))

			remoteAddr := conn.RemoteAddrStr()
			remotePort := conn.RemotePort
			// For inbound (server) connections, incoming data is the request.
			// Swap to keep sendBuf=request, recvBuf=response in the reassembler.
			if conn.Direction == conntrack.ConnInbound {
				// Store trace context for intra-process parent-child linking.
				// When the request arrives, generate/extract trace context so
				// outbound CLIENT spans (e.g., DB queries) can inherit it.
				ctxKey := uint64(pid)<<32 | uint64(tid)
				if _, loaded := a.threadCtx.Load(ctxKey); !loaded {
					traceCtx := protocol.ExtractTraceContext(data)
					tctx := &threadTraceCtx{Created: time.Now()}
					if traceCtx.TraceID != "" {
						tctx.TraceID = traceCtx.TraceID
					} else {
						tctx.TraceID = traces.GenerateTraceID()
					}
					tctx.SpanID = traces.GenerateSpanID()
					a.threadCtx.Store(ctxKey, tctx)
				}
				a.reassembler.AppendSend(pid, tid, fd, data, remoteAddr, remotePort, false)
				a.reassembler.SetDirection(pid, fd, 1) // 1=inbound; set after AppendSend creates the stream
			} else {
				a.reassembler.AppendRecv(pid, tid, fd, data, remoteAddr, remotePort, false)
			}
		},

		OnClose: func(pid, tid uint32, fd int32, ts uint64) {
			a.reassembler.RemoveStream(pid, fd, tid)
			a.connTracker.Remove(pid, fd)
		},
	}

	// C9 fix: Reassembler sends pairs to channel instead of calling callbacks directly.
	// This ensures the reassembler's stream lock is released before trace processing begins.
	a.reassembler.OnPair(func(pair *reassembly.RequestPair) {
		select {
		case a.pairCh <- pair:
		default:
			a.logger.Warn("pair channel full, dropping pair",
				zap.Uint32("pid", pair.PID),
				zap.Int32("fd", pair.FD),
			)
		}
	})

	// C9 fix: TraceProcessor sends spans to channel instead of calling callbacks directly.
	a.traceProc.OnSpan(func(span *traces.Span) {
		select {
		case a.spanCh <- span:
		default:
			a.logger.Warn("span channel full, dropping span",
				zap.String("name", span.Name),
			)
		}
	})

	// C9 fix: LogCollector sends logs to channel.
	if a.logCollector != nil {
		a.logCollector.OnLog(func(record *logs.LogRecord) {
			select {
			case a.logCh <- record:
			default:
				a.logger.Warn("log channel full, dropping log")
			}
		})
	}

	// Wire: MetricsCollector → Exporter (no lock concerns - simple callback)
	if a.metricsColl != nil {
		a.metricsColl.OnMetric(func(m *metrics.Metric) {
			a.exporter.ExportMetric(&export.Metric{
				Name:        m.Name,
				Description: m.Description,
				Unit:        m.Unit,
				Type:        export.MetricType(m.Type),
				Value:       m.Value,
				Timestamp:   m.Timestamp,
				Labels:      m.Labels,
			})
		})
	}

	// Start all subsystems
	if err := a.exporter.Start(ctx); err != nil {
		return fmt.Errorf("start exporter: %w", err)
	}

	if cfg.Hook.Enabled {
		a.hookMgr = hook.NewManager(cfg.Hook.SocketPath, callbacks, a.logger)
		if err := a.hookMgr.Start(ctx); err != nil {
			return fmt.Errorf("start hook manager: %w", err)
		}
	}

	if a.logCollector != nil {
		if err := a.logCollector.Start(ctx); err != nil {
			a.logger.Warn("log collector start error", zap.Error(err))
		}
	}

	if a.metricsColl != nil {
		if err := a.metricsColl.Start(ctx); err != nil {
			a.logger.Warn("metrics collector start error", zap.Error(err))
		}
	}

	if a.correlation != nil {
		if err := a.correlation.Start(ctx); err != nil {
			a.logger.Warn("correlation engine start error", zap.Error(err))
		}
	}

	// C9 fix: Start decoupled dispatch goroutines.
	// These goroutines are the only ones that call into correlation/exporter,
	// ensuring no lock ordering issues across subsystem boundaries.
	a.wg.Add(1)
	go a.pairDispatchLoop(ctx)

	a.wg.Add(1)
	go a.spanDispatchLoop(ctx)

	a.wg.Add(1)
	go a.logDispatchLoop(ctx)

	// Start periodic cleanup
	a.wg.Add(1)
	go a.cleanupLoop(ctx)

	// Start request metrics reporting
	if a.requestMetrics != nil {
		metricsCtx, metricsCancel := context.WithCancel(ctx)
		a.metricsCancel = metricsCancel
		a.wg.Add(1)
		go a.requestMetricsLoop(metricsCtx)
	}

	a.logger.Info("agent started",
		zap.Bool("hook", cfg.Hook.Enabled),
		zap.Bool("logs", cfg.Logs.Enabled),
		zap.Bool("metrics", cfg.Metrics.Enabled),
		zap.Bool("correlation", cfg.Correlation.Enabled),
	)

	return nil
}

// pairDispatchLoop reads request pairs from the channel and processes them.
// This runs outside any reassembler locks.
func (a *Agent) pairDispatchLoop(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case pair := <-a.pairCh:
			a.enrichPairContext(pair)
			connInfo := a.connTracker.Lookup(pair.PID, pair.FD)
			a.traceProc.ProcessPair(pair, connInfo)
		case <-ctx.Done():
			// Drain remaining pairs
			for {
				select {
				case pair := <-a.pairCh:
					a.enrichPairContext(pair)
					connInfo := a.connTracker.Lookup(pair.PID, pair.FD)
					a.traceProc.ProcessPair(pair, connInfo)
				default:
					return
				}
			}
		}
	}
}

// enrichPairContext applies intra-process parent-child trace context to a pair.
// For inbound SERVER spans: use the stored context as this span's IDs, then clear.
// For outbound CLIENT spans: use the stored context as parent.
func (a *Agent) enrichPairContext(pair *reassembly.RequestPair) {
	ctxKey := uint64(pair.PID)<<32 | uint64(pair.TID)
	val, ok := a.threadCtx.Load(ctxKey)
	if !ok {
		return
	}
	tctx := val.(*threadTraceCtx)
	// Only apply if context is recent (within 30s)
	if time.Since(tctx.Created) > 30*time.Second {
		a.threadCtx.Delete(ctxKey)
		return
	}
	pair.ParentTraceID = tctx.TraceID
	pair.ParentSpanID = tctx.SpanID

	// For inbound connections, the SERVER span consumes the context
	connInfo := a.connTracker.Lookup(pair.PID, pair.FD)
	if connInfo != nil && connInfo.Direction == conntrack.ConnInbound {
		a.threadCtx.Delete(ctxKey)
	}
}

// spanDispatchLoop reads spans from the channel and dispatches to correlation/exporter.
// This runs outside any trace processor locks.
func (a *Agent) spanDispatchLoop(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case span := <-a.spanCh:
			a.processSpan(span)
		case <-ctx.Done():
			// Drain remaining spans
			for {
				select {
				case span := <-a.spanCh:
					a.processSpan(span)
				default:
					return
				}
			}
		}
	}
}

// processSpan enriches and exports a single span.
func (a *Agent) processSpan(span *traces.Span) {
	// Enrich with service name
	if a.discoverer != nil && span.ServiceName == "" {
		span.ServiceName = a.discoverer.GetServiceName(span.PID)
	}

	// Register with correlation engine
	if a.correlation != nil {
		a.correlation.RegisterSpanStart(
			span.PID, span.TID,
			span.TraceID, span.SpanID, span.ParentSpanID,
			span.ServiceName, span.Name,
		)
	}

	// Record request metrics
	if a.requestMetrics != nil {
		a.requestMetrics.RecordSpan(span)
	}

	// Export
	a.exporter.ExportSpan(span)
}

// logDispatchLoop reads logs from the channel and dispatches to correlation/exporter.
func (a *Agent) logDispatchLoop(ctx context.Context) {
	defer a.wg.Done()
	for {
		select {
		case record := <-a.logCh:
			a.processLog(record)
		case <-ctx.Done():
			// Drain remaining logs
			for {
				select {
				case record := <-a.logCh:
					a.processLog(record)
				default:
					return
				}
			}
		}
	}
}

// processLog enriches and exports a single log record.
func (a *Agent) processLog(record *logs.LogRecord) {
	// Try to enrich with trace context
	if a.correlation != nil {
		a.correlation.EnrichLog(record)
	}

	// Convert and export
	// R3.1: Map LogLevel enum to OTEL SeverityNumber
	a.exporter.ExportLog(&export.LogRecord{
		Timestamp:      record.Timestamp,
		ObservedTime:   time.Now(),
		Body:           record.Body,
		Level:          record.Level.String(),
		SeverityNumber: logLevelToSeverityNumber(record.Level),
		Attributes:     record.Attributes,
		PID:            record.PID,
		TID:            record.TID,
		TraceID:        record.TraceID,
		SpanID:         record.SpanID,
		ServiceName:    record.ServiceName,
		Source:         record.Source,
		FilePath:       record.FilePath,
	})
}

// Stop shuts down all subsystems gracefully.
func (a *Agent) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cancel != nil {
		a.cancel()
	}

	if a.hookMgr != nil {
		a.hookMgr.Stop()
	}

	if a.logCollector != nil {
		a.logCollector.Stop()
	}

	if a.metricsColl != nil {
		a.metricsColl.Stop()
	}

	if a.correlation != nil {
		a.correlation.Stop()
	}

	// Wait for dispatch goroutines to drain their channels
	a.wg.Wait()

	if a.exporter != nil {
		a.exporter.Stop()
	}

	// Log final stats
	spans, logCount, metricCount := a.exporter.Stats()
	a.logger.Info("agent stopped",
		zap.Int64("total_spans", spans),
		zap.Int64("total_logs", logCount),
		zap.Int64("total_metrics", metricCount),
		zap.Int("active_connections", a.connTracker.Count()),
	)

	return nil
}

// Reload applies new configuration with subsystem start/stop.
// If a signal was disabled and is now enabled, start its subsystem.
// If a signal was enabled and is now disabled, stop its subsystem.
func (a *Agent) Reload(cfg *config.Config) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	oldCfg := a.cfg.Load()
	a.cfg.Store(cfg)

	// Logs: start/stop collector
	if !oldCfg.Logs.Enabled && cfg.Logs.Enabled {
		a.startLogs()
	} else if oldCfg.Logs.Enabled && !cfg.Logs.Enabled {
		a.stopLogs()
	}

	// Metrics: start/stop collector
	if !oldCfg.Metrics.Enabled && cfg.Metrics.Enabled {
		a.startMetrics()
	} else if oldCfg.Metrics.Enabled && !cfg.Metrics.Enabled {
		a.stopMetrics()
	}

	a.logger.Info("configuration reloaded",
		zap.Bool("logs", cfg.Logs.Enabled),
		zap.Bool("metrics", cfg.Metrics.Enabled),
		zap.Bool("tracing", cfg.Tracing.Enabled),
		zap.Bool("profiling", cfg.Profiling.Enabled),
	)
	return nil
}

func (a *Agent) startLogs() {
	if a.logCollector != nil {
		return // already running
	}
	cfg := a.cfg.Load()
	a.logCollector = logs.NewCollector(&cfg.Logs, a.logger)
	a.logCollector.OnLog(func(record *logs.LogRecord) {
		select {
		case a.logCh <- record:
		default:
			a.logger.Warn("log channel full, dropping log")
		}
	})
	if err := a.logCollector.Start(a.ctx); err != nil {
		a.logger.Warn("log collector start error on reload", zap.Error(err))
	}
	a.logger.Info("log collector started via reload")
}

func (a *Agent) stopLogs() {
	if a.logCollector == nil {
		return
	}
	a.logCollector.Stop()
	a.logCollector = nil
	a.logger.Info("log collector stopped via reload")
}

func (a *Agent) startMetrics() {
	if a.metricsColl != nil {
		return // already running
	}
	cfg := a.cfg.Load()
	a.metricsColl = metrics.NewCollector(&cfg.Metrics, a.logger)
	a.requestMetrics = rmetrics.NewRequestMetrics(cfg.Metrics.Request.Buckets)
	a.metricsColl.OnMetric(func(m *metrics.Metric) {
		a.exporter.ExportMetric(&export.Metric{
			Name:        m.Name,
			Description: m.Description,
			Unit:        m.Unit,
			Type:        export.MetricType(m.Type),
			Value:       m.Value,
			Timestamp:   m.Timestamp,
			Labels:      m.Labels,
		})
	})
	if err := a.metricsColl.Start(a.ctx); err != nil {
		a.logger.Warn("metrics collector start error on reload", zap.Error(err))
	}
	metricsCtx, metricsCancel := context.WithCancel(a.ctx)
	a.metricsCancel = metricsCancel
	a.wg.Add(1)
	go a.requestMetricsLoop(metricsCtx)
	a.logger.Info("metrics collector started via reload")
}

func (a *Agent) stopMetrics() {
	if a.metricsColl == nil {
		return
	}
	// Cancel request metrics loop first, then wait for it to exit
	if a.metricsCancel != nil {
		a.metricsCancel()
		a.metricsCancel = nil
	}
	a.metricsColl.Stop()
	a.metricsColl = nil
	a.requestMetrics = nil
	a.logger.Info("metrics collector stopped via reload")
}

func (a *Agent) cleanupLoop(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Clean stale connections (5 min timeout)
			staleConns := a.connTracker.CleanStale(5 * time.Minute)
			staleStreams := a.reassembler.CleanStale(5 * time.Minute)

			if staleConns > 0 || staleStreams > 0 {
				a.logger.Debug("cleanup",
					zap.Int("stale_connections", staleConns),
					zap.Int("stale_streams", staleStreams),
					zap.Int("active_connections", a.connTracker.Count()),
					zap.Int("active_streams", a.reassembler.StreamCount()),
				)
			}

		case <-ctx.Done():
			return
		}
	}
}

// logLevelToSeverityNumber maps logs.LogLevel to OTEL SeverityNumber.
// OTEL SeverityNumber: TRACE=1-4, DEBUG=5-8, INFO=9-12, WARN=13-16, ERROR=17-20, FATAL=21-24.
func logLevelToSeverityNumber(level logs.LogLevel) int32 {
	switch level {
	case logs.LevelTrace:
		return 1
	case logs.LevelDebug:
		return 5
	case logs.LevelInfo:
		return 9
	case logs.LevelWarn:
		return 13
	case logs.LevelError:
		return 17
	case logs.LevelFatal:
		return 21
	default:
		return 0 // UNSPECIFIED
	}
}

func (a *Agent) requestMetricsLoop(ctx context.Context) {
	defer a.wg.Done()

	// C10 fix: read config via atomic pointer
	cfg := a.cfg.Load()
	interval := cfg.Metrics.Interval
	if interval == 0 {
		interval = 15 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			for _, m := range a.requestMetrics.Collect(now) {
				em := &export.Metric{
					Name:        m.Name,
					Description: m.Description,
					Unit:        m.Unit,
					Type:        export.MetricType(m.Type),
					Value:       m.Value,
					Timestamp:   m.Timestamp,
					Labels:      m.Labels,
				}
				// Pass through histogram data for proper OTLP export
				if m.Histogram != nil {
					buckets := make([]export.HistogramBucket, len(m.Histogram.Buckets))
					for i, b := range m.Histogram.Buckets {
						buckets[i] = export.HistogramBucket{
							UpperBound: b.UpperBound,
							Count:      b.Count,
						}
					}
					em.Histogram = &export.HistogramValue{
						Count:   m.Histogram.Count,
						Sum:     m.Histogram.Sum,
						Buckets: buckets,
					}
				}
				a.exporter.ExportMetric(em)
			}

		case <-ctx.Done():
			return
		}
	}
}
