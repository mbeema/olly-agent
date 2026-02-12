// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package agent

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/conntrack"
	"github.com/mbeema/olly/pkg/correlation"
	"github.com/mbeema/olly/pkg/discovery"
	"github.com/mbeema/olly/pkg/export"
	"github.com/mbeema/olly/pkg/health"
	"github.com/mbeema/olly/pkg/hook"
	hookebpf "github.com/mbeema/olly/pkg/hook/ebpf"
	"github.com/mbeema/olly/pkg/logs"
	"github.com/mbeema/olly/pkg/metrics"
	rmetrics "github.com/mbeema/olly/pkg/metrics"
	"github.com/mbeema/olly/pkg/profiling"
	"github.com/mbeema/olly/pkg/protocol"
	"github.com/mbeema/olly/pkg/reassembly"
	"github.com/mbeema/olly/pkg/redact"
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

	hookProvider    hook.HookProvider
	healthServer    *health.Server
	healthStats     *health.Stats
	redactor        *redact.Redactor
	sampler         *traces.Sampler
	logParser       *logs.Parser
	connTracker     *conntrack.Tracker
	reassembler     *reassembly.Reassembler
	traceProc       *traces.Processor
	traceStitcher   *traces.Stitcher
	correlation     *correlation.Engine
	logCollector    *logs.Collector
	metricsColl     *metrics.Collector
	requestMetrics  *rmetrics.RequestMetrics
	processColl     *metrics.ProcessCollector
	containerColl   *metrics.ContainerCollector
	exporter        *export.Manager
	discoverer      *discovery.Discoverer
	serviceMap      *servicemap.Generator
	profiler        profiling.Profiler

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
	TraceID      string
	SpanID       string // injected via sk_msg → becomes CLIENT span's own spanID
	ServerSpanID string // SERVER span's own spanID (CLIENT spans reference this as parent)
	ParentSpanID string // from incoming traceparent header (cross-service linking)
	Created      time.Time
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

	// Initialize health stats
	a.healthStats = health.NewStats()

	// Initialize PII redactor
	var extraRules []redact.Rule
	for _, r := range cfg.Redaction.Rules {
		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			logger.Warn("invalid redaction rule pattern", zap.String("name", r.Name), zap.Error(err))
			continue
		}
		extraRules = append(extraRules, redact.Rule{
			Name:        r.Name,
			Pattern:     compiled,
			Replacement: r.Replacement,
		})
	}
	a.redactor = redact.New(cfg.Redaction.Enabled, extraRules)

	// Initialize trace sampler
	samplingRate := cfg.Tracing.Sampling.Rate
	if samplingRate == 0 {
		samplingRate = 1.0 // default: keep all
	}
	a.sampler = traces.NewSampler(samplingRate)

	// Initialize log parser for hook-captured log writes
	a.logParser = logs.NewParser()

	// Initialize connection tracker
	a.connTracker = conntrack.NewTracker()

	// Initialize reassembler
	a.reassembler = reassembly.NewReassembler(logger)

	// Initialize trace processor
	a.traceProc = traces.NewProcessor(logger)

	// Initialize cross-service trace stitcher
	a.traceStitcher = traces.NewStitcher(cfg.Correlation.Window, logger)

	// Initialize correlation engine
	a.correlation = correlation.NewEngine(cfg.Correlation.Window, logger)

	// Initialize export manager
	serviceName := cfg.ServiceName
	if serviceName == "auto" || serviceName == "" {
		serviceName = "olly-agent"
	}

	exporter, err := export.NewManager(&cfg.Exporters, serviceName, logger, &cfg.Profiling.Pyroscope)
	if err != nil {
		return nil, fmt.Errorf("create exporter: %w", err)
	}
	a.exporter = exporter

	// Initialize log collector
	if cfg.Logs.Enabled {
		logsCfg := cfg.Logs
		// Append security log sources if security logging is enabled
		if logsCfg.Security.Enabled {
			logsCfg.Sources = append(logsCfg.Sources, logs.DefaultSecurityLogSources()...)
			logger.Info("security/audit log collection enabled")
		}
		a.logCollector = logs.NewCollector(&logsCfg, logger)
	}

	// Initialize metrics collector
	if cfg.Metrics.Enabled {
		a.metricsColl = metrics.NewCollector(&cfg.Metrics, logger)
		a.requestMetrics = rmetrics.NewRequestMetrics(cfg.Metrics.Request.Buckets)

		// Per-process metrics
		if cfg.Metrics.PerProcess.Enabled {
			a.processColl = metrics.NewProcessCollector(logger)
			for _, pid := range cfg.Metrics.PerProcess.PIDs {
				a.processColl.AddPID(pid)
			}
		}

		// Container metrics (auto-detected)
		if cfg.Metrics.Container.Enabled {
			a.containerColl = metrics.NewContainerCollector(logger)
		}
	}

	// Initialize discovery
	if cfg.Discovery.Enabled {
		a.discoverer = discovery.NewDiscoverer(cfg.Discovery.EnvVars, cfg.Discovery.PortMappings, logger)
	}

	// Initialize profiler
	if cfg.Profiling.Enabled {
		a.profiler = profiling.New(&profiling.Config{
			SampleRate: cfg.Profiling.SampleRate,
			Interval:   cfg.Profiling.Interval,
			OnDemand:   cfg.Profiling.OnDemand,
			Logger:     logger,
		})
	}

	// Initialize service map
	a.serviceMap = servicemap.NewGenerator(logger)

	// Select hook provider: prefer eBPF, fall back to socket manager, stub if unsupported
	if cfg.Hook.Enabled {
		a.hookProvider = selectHookProvider(cfg, logger)
	}

	return a, nil
}

// selectHookProvider picks the best available hook provider for the platform.
func selectHookProvider(cfg *config.Config, logger *zap.Logger) hook.HookProvider {
	// Try eBPF first (Linux 5.8+ with BTF)
	support := hookebpf.Detect()
	if support.Available {
		logger.Info("eBPF support detected",
			zap.String("kernel", support.KernelVersion),
			zap.Bool("btf", support.HasBTF),
		)
		return hookebpf.NewProvider(cfg, logger)
	}

	logger.Info("eBPF not available, checking fallback options",
		zap.String("reason", support.Reason),
	)

	// Fall back to legacy socket-based manager if socket_path is configured
	if cfg.Hook.SocketPath != "" {
		logger.Info("using legacy socket hook provider",
			zap.String("socket", cfg.Hook.SocketPath),
		)
		return hook.NewManager(cfg.Hook.SocketPath, logger)
	}

	// Stub provider — agent runs without hook tracing
	return hookebpf.NewStubProvider(support.Reason, logger)
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

			// Auto-discover PIDs for per-process metrics
			if a.processColl != nil {
				a.processColl.AddPID(pid)
			}

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
				// Always create fresh context for each inbound request.
				// Previous context is NOT deleted in enrichPairContext (to allow
				// CLIENT spans to inherit it), so we must overwrite here when
				// the next request arrives on the same thread.
				{
					tctx := &threadTraceCtx{Created: time.Now()}

					// Priority 1: Extract traceparent from HTTP headers in the data.
					// This captures injected headers from upstream sk_msg and gives
					// us both traceID (for trace continuity) and parentSpanID.
					traceCtx := protocol.ExtractTraceContext(data)
					if traceCtx.TraceID != "" {
						tctx.TraceID = traceCtx.TraceID
						tctx.ParentSpanID = traceCtx.SpanID
						a.logger.Debug("extracted traceparent from inbound data",
							zap.Uint32("pid", pid), zap.Uint32("tid", tid),
							zap.String("traceID", traceCtx.TraceID),
							zap.String("parentSpanID", traceCtx.SpanID),
							zap.Uint16("port", remotePort))
					}

					// Priority 2: Check BPF-generated trace context.
					// BPF generates context synchronously in kretprobe_read,
					// extracting traceID from incoming traceparent or generating random.
					if tctx.TraceID == "" {
						if injector, ok := a.hookProvider.(hook.TraceInjector); ok {
							if bpfTraceID, bpfSpanID, bpfOK := injector.GetTraceContext(pid, tid); bpfOK {
								tctx.TraceID = bpfTraceID
								tctx.SpanID = bpfSpanID
								a.logger.Debug("using BPF-generated trace context",
									zap.Uint32("pid", pid), zap.Uint32("tid", tid),
									zap.String("traceID", bpfTraceID))
							}
						}
					}

					// Priority 3: Generate new trace ID
					if tctx.TraceID == "" {
						tctx.TraceID = traces.GenerateTraceID()
					}
					if tctx.SpanID == "" {
						tctx.SpanID = traces.GenerateSpanID()
					}
					// ServerSpanID is always a separate ID for the SERVER span.
					// tctx.SpanID is what gets injected via sk_msg and becomes
					// the CLIENT span's own spanID. This creates a proper chain:
					// SERVER(ServerSpanID) → CLIENT(SpanID) → downstream SERVER(parent=SpanID)
					tctx.ServerSpanID = traces.GenerateSpanID()
					a.threadCtx.Store(ctxKey, tctx)

					// Populate BPF trace context for sk_msg injection.
					// If BPF already generated it, this overwrites with the
					// same trace ID (agent may have generated a different spanID).
					if injector, ok := a.hookProvider.(hook.TraceInjector); ok {
						injector.SetTraceContext(pid, tid, tctx.TraceID, tctx.SpanID)
					}
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

		// R6: Capture log writes with PID+TID for trace correlation
		OnLogWrite: func(pid, tid uint32, fd int32, data []byte, ts uint64) {
			if cfg.Hook.LogCaptureEnabled() {
				a.processHookLog(pid, tid, fd, data, ts)
			}
		},
	}

	// C9 fix: Reassembler sends pairs to channel instead of calling callbacks directly.
	// This ensures the reassembler's stream lock is released before trace processing begins.
	a.reassembler.OnPair(func(pair *reassembly.RequestPair) {
		// Enrich context HERE (in ring buffer reader goroutine) to avoid race:
		// OnDataIn creates threadCtx in this same goroutine, so the context
		// is guaranteed to still be for this request. If we waited until
		// pairDispatchLoop (separate goroutine), a new inbound request could
		// overwrite the context before the pair is processed.
		a.enrichPairContext(pair)
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

	if cfg.Hook.Enabled && a.hookProvider != nil {
		if err := a.hookProvider.Start(ctx, callbacks); err != nil {
			a.logger.Warn("hook provider failed to start, falling back to stub",
				zap.String("provider", a.hookProvider.Name()),
				zap.Error(err),
			)
			// Fall back to stub — agent runs without tracing
			a.hookProvider = hookebpf.NewStubProvider(err.Error(), a.logger)
			if err := a.hookProvider.Start(ctx, callbacks); err != nil {
				a.logger.Warn("stub provider also failed", zap.Error(err))
			}
		}
		a.logger.Info("hook provider started", zap.String("provider", a.hookProvider.Name()))
		// Set initial tracing state based on on_demand config
		if cfg.Hook.OnDemand {
			a.logger.Info("on-demand tracing: starting dormant (use 'olly trace start' to activate)")
		} else {
			if err := a.hookProvider.EnableTracing(); err != nil {
				a.logger.Warn("failed to enable tracing", zap.Error(err))
			}
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

	// Start per-process metrics
	if a.processColl != nil {
		a.processColl.OnMetric(func(m *metrics.Metric) {
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
		if err := a.processColl.Start(ctx, cfg.Metrics.Interval); err != nil {
			a.logger.Warn("process metrics start error", zap.Error(err))
		}
	}

	// Start container metrics
	if a.containerColl != nil {
		a.containerColl.OnMetric(func(m *metrics.Metric) {
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
		if err := a.containerColl.Start(ctx, cfg.Metrics.Interval); err != nil {
			a.logger.Warn("container metrics start error", zap.Error(err))
		}
	}

	if a.correlation != nil {
		if err := a.correlation.Start(ctx); err != nil {
			a.logger.Warn("correlation engine start error", zap.Error(err))
		}
	}

	// Start profiler
	if a.profiler != nil {
		if a.discoverer != nil {
			a.profiler.SetServiceResolver(func(pid uint32) string {
				return a.discoverer.GetServiceName(pid)
			})
		}
		a.profiler.OnProfile(func(p *profiling.Profile) {
			a.exporter.ExportProfile(p)
		})
		if err := a.profiler.Start(ctx); err != nil {
			a.logger.Warn("profiler start error", zap.Error(err))
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

	// Start health server
	if cfg.Health.Enabled {
		a.healthServer = health.NewServer(cfg.Health.Port, "dev", a.healthStats, a.logger)
		if err := a.healthServer.Start(ctx); err != nil {
			a.logger.Warn("health server start error", zap.Error(err))
		} else {
			a.healthServer.SetReady(true)
		}
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
			// enrichPairContext already called in OnPair callback (same goroutine
			// as OnDataIn, avoiding race with thread context overwrites).
			connInfo := a.connTracker.Lookup(pair.PID, pair.FD)
			a.traceProc.ProcessPair(pair, connInfo)
		case <-ctx.Done():
			// Drain remaining pairs
			for {
				select {
				case pair := <-a.pairCh:
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
		// Fallback: search by PID only. Go goroutines execute on different
		// OS threads, so the PG query may run on a different TID than the
		// inbound HTTP handler. Find the most recent context for this PID.
		var bestCtx *threadTraceCtx
		a.threadCtx.Range(func(key, value any) bool {
			k, ok := key.(uint64)
			if !ok {
				return true
			}
			if uint32(k>>32) == pair.PID {
				tctx, ok := value.(*threadTraceCtx)
				if !ok {
					return true
				}
				if bestCtx == nil || tctx.Created.After(bestCtx.Created) {
					bestCtx = tctx
				}
			}
			return true
		})
		if bestCtx == nil {
			return
		}
		val = bestCtx
	}
	tctx, ok := val.(*threadTraceCtx)
	if !ok {
		return
	}
	// Only apply if context is recent (within 30s)
	if time.Since(tctx.Created) > 30*time.Second {
		a.threadCtx.Delete(ctxKey)
		// Clean up leaked BPF map entry for this expired thread context
		if injector, ok := a.hookProvider.(hook.TraceInjector); ok {
			injector.ClearTraceContext(pair.PID, pair.TID)
		}
		return
	}
	pair.ParentTraceID = tctx.TraceID
	pair.ParentSpanID = tctx.ServerSpanID // SERVER span's own ID

	// For inbound connections, the SERVER span uses the context but does NOT
	// delete it. Subsequent outbound CLIENT spans on the same thread need to
	// inherit the trace ID to maintain end-to-end trace continuity.
	// Context is cleaned up when the next inbound request arrives (line 303
	// only stores if !loaded) or by the 30s TTL above.
	connInfo := a.connTracker.Lookup(pair.PID, pair.FD)
	if connInfo != nil && connInfo.Direction == conntrack.ConnInbound {
		// Don't delete context — CLIENT spans on this thread still need it.
		// Clear BPF trace context since sk_msg injection already happened.
		if injector, ok := a.hookProvider.(hook.TraceInjector); ok {
			injector.ClearTraceContext(pair.PID, pair.TID)
		}
	} else {
		// Outbound CLIENT span: pass the sk_msg-injected spanID so the
		// CLIENT span uses it as its own spanID (matching what downstream sees)
		pair.InjectedSpanID = tctx.SpanID
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
	a.healthStats.SpansReceived.Add(1)

	// Apply sampling (always keep errors)
	isError := span.Status == traces.StatusError
	if !a.sampler.ShouldSample(span.TraceID, isError) {
		a.healthStats.SpansDropped.Add(1)
		return
	}

	// Enrich with service name
	if a.discoverer != nil && span.ServiceName == "" {
		span.ServiceName = a.discoverer.GetServiceName(span.PID)
	}

	// Apply PII redaction to sensitive attributes
	a.redactor.RedactMap(span.Attributes, "db.query.text", "http.request.header.authorization", "url.query")

	// Normalize SQL queries
	if stmt, ok := span.Attributes["db.query.text"]; ok && stmt != "" {
		span.Attributes["db.query.text"] = redact.NormalizeSQL(stmt)
	}

	// Cross-service trace stitching: CLIENT spans are stored,
	// SERVER spans are matched against stored CLIENT spans.
	if a.traceStitcher != nil {
		a.traceStitcher.ProcessSpan(span)
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
	a.healthStats.SpansExported.Add(1)

	// Mark span as complete so correlation engine tracks proper time window
	if a.correlation != nil {
		a.correlation.RegisterSpanEnd(span.PID, span.TID)
	}
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
	a.healthStats.LogsReceived.Add(1)

	// Apply PII redaction to log body
	record.Body = a.redactor.Redact(record.Body)

	// Try to enrich with trace context
	if a.correlation != nil {
		a.correlation.EnrichLog(record)
	}

	// Convert and export
	// R3.1: Map LogLevel enum to OTEL SeverityNumber
	a.healthStats.LogsExported.Add(1)
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

// processHookLog handles log data captured by the write() hook in libolly.c.
// The key advantage: PID and TID come from the syscall context, enabling
// automatic correlation with active traces via the correlation engine.
func (a *Agent) processHookLog(pid, tid uint32, fd int32, data []byte, ts uint64) {
	// Binary filter: skip if >10% non-printable bytes in first 256 bytes
	checkLen := len(data)
	if checkLen > 256 {
		checkLen = 256
	}
	nonPrintable := 0
	for i := 0; i < checkLen; i++ {
		b := data[i]
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintable++
		}
	}
	if checkLen > 0 && nonPrintable*10 > checkLen {
		return // binary data, not a log
	}

	// Split on newlines and process each line
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		record := a.logParser.Parse(string(line), "auto")
		// Override PID/TID from syscall context — this is the key advantage
		record.PID = int(pid)
		record.TID = int(tid)
		record.Source = "hook"

		select {
		case a.logCh <- record:
		default:
			// Channel full, drop
		}
	}
}

// Stop shuts down all subsystems gracefully.
func (a *Agent) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.cancel != nil {
		a.cancel()
	}

	if a.healthServer != nil {
		a.healthServer.SetReady(false)
		a.healthServer.Stop()
	}

	if a.hookProvider != nil {
		a.hookProvider.Stop()
	}

	if a.logCollector != nil {
		a.logCollector.Stop()
	}

	if a.metricsColl != nil {
		a.metricsColl.Stop()
	}

	if a.processColl != nil {
		a.processColl.Stop()
	}

	if a.containerColl != nil {
		a.containerColl.Stop()
	}

	if a.profiler != nil {
		a.profiler.Stop()
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
	spans, logCount, metricCount, profileCount := a.exporter.Stats()
	a.logger.Info("agent stopped",
		zap.Int64("total_spans", spans),
		zap.Int64("total_logs", logCount),
		zap.Int64("total_metrics", metricCount),
		zap.Int64("total_profiles", profileCount),
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

	// Profiling: start/stop profiler
	if !oldCfg.Profiling.Enabled && cfg.Profiling.Enabled {
		a.startProfiling()
	} else if oldCfg.Profiling.Enabled && !cfg.Profiling.Enabled {
		a.stopProfiling()
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

func (a *Agent) startProfiling() {
	if a.profiler != nil {
		return // already running
	}
	cfg := a.cfg.Load()
	a.profiler = profiling.New(&profiling.Config{
		SampleRate: cfg.Profiling.SampleRate,
		Interval:   cfg.Profiling.Interval,
		OnDemand:   cfg.Profiling.OnDemand,
		Logger:     a.logger,
	})
	if a.discoverer != nil {
		a.profiler.SetServiceResolver(func(pid uint32) string {
			return a.discoverer.GetServiceName(pid)
		})
	}
	a.profiler.OnProfile(func(p *profiling.Profile) {
		a.exporter.ExportProfile(p)
	})
	if err := a.profiler.Start(a.ctx); err != nil {
		a.logger.Warn("profiler start error on reload", zap.Error(err))
	}
	a.logger.Info("profiler started via reload")
}

func (a *Agent) stopProfiling() {
	if a.profiler == nil {
		return
	}
	a.profiler.Stop()
	a.profiler = nil
	a.logger.Info("profiler stopped via reload")
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

			// Clean stale stitching entries
			staleStitched := 0
			if a.traceStitcher != nil {
				staleStitched = a.traceStitcher.Cleanup()
			}

			// Clean stale thread trace contexts (and their BPF map entries)
			staleThreadCtx := 0
			a.threadCtx.Range(func(key, value any) bool {
				tctx, ok := value.(*threadTraceCtx)
				if !ok {
					a.threadCtx.Delete(key)
					return true
				}
				if time.Since(tctx.Created) > 30*time.Second {
					a.threadCtx.Delete(key)
					staleThreadCtx++
					// Clear leaked BPF map entry
					if injector, ok := a.hookProvider.(hook.TraceInjector); ok {
						k, ok := key.(uint64)
						if ok {
							pid := uint32(k >> 32)
							tid := uint32(k & 0xFFFFFFFF)
							injector.ClearTraceContext(pid, tid)
						}
					}
				}
				return true
			})

			if staleConns > 0 || staleStreams > 0 || staleStitched > 0 || staleThreadCtx > 0 {
				a.logger.Debug("cleanup",
					zap.Int("stale_connections", staleConns),
					zap.Int("stale_streams", staleStreams),
					zap.Int("stale_stitched", staleStitched),
					zap.Int("stale_thread_ctx", staleThreadCtx),
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
