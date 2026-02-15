// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package agent

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"strings"
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
	genaiMetrics    atomic.Pointer[rmetrics.GenAIMetrics]
	mcpMetrics      atomic.Pointer[rmetrics.MCPMetrics]
	processColl     *metrics.ProcessCollector
	containerColl   *metrics.ContainerCollector
	exporter        *export.Manager
	discoverer      *discovery.Discoverer
	serviceMap      *servicemap.Generator
	profiler        profiling.Profiler

	// Configurable trace context lifetime (replaces hardcoded 30s)
	maxRequestDuration time.Duration

	// Decoupled channels (C9 fix) - prevent callback deadlocks
	pairCh chan *reassembly.RequestPair
	logCh  chan *logs.LogRecord
	spanCh chan *traces.Span

	// Trace filtering (compiled from config)
	excludedAddrs   map[string]bool // connection-level: skip these remote IPs entirely
	excludePaths    []string        // span-level: drop spans matching these URL path prefixes
	includeServices map[string]bool // span-level: if non-empty, only export these services

	// Connection-scoped trace context for intra-process parent-child linking.
	// FD-keyed instead of TID-keyed: survives goroutine migration, handles
	// concurrent requests, and provides O(1) PID fallback.
	connCtx         sync.Map // key: uint64(PID)<<32|uint64(uint32(FD)) -> *connTraceCtx
	threadInboundFD sync.Map // key: uint64(PID)<<32|uint64(TID)        -> int32 (inbound FD)
	fdCausal        sync.Map // key: uint64(PID)<<32|uint64(uint32(FD)) -> *causalEntry
	pidActiveCtx    sync.Map // key: uint32(PID)                        -> *pidInboundSet (active inbound FDs)
	causalCtxSnap   sync.Map // key: uint64(PID)<<32|uint64(uint32(outbound FD)) -> *causalCtxQueue

	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	metricsCancel context.CancelFunc // per-subsystem cancel for request metrics loop
	wg            sync.WaitGroup
}

// connTraceCtx holds trace context for an active inbound request on a connection.
// Keyed by PID+FD (connection-scoped) instead of PID+TID (thread-scoped) to
// survive Go goroutine migration and handle concurrent requests correctly.
type connTraceCtx struct {
	TraceID      string
	SpanID       string // injected via sk_msg → becomes CLIENT span's own spanID
	ServerSpanID string // SERVER span's own spanID (CLIENT spans reference this as parent)
	ParentSpanID string // from incoming traceparent header (cross-service linking)
	ReadTID      uint32 // TID that read the inbound request (for sk_msg injection validation)
	Created      time.Time
}

// causalEntry records which inbound FD caused an outbound write.
// Written in OnDataOut, read in enrichPairContext Layer 1.
type causalEntry struct {
	InboundFD int32
	Timestamp time.Time
}

// causalCtxSnapshot is a minimal snapshot of trace context captured at
// PushCausalFD time (OnDataOut). Used by enrichPairContext Layer 0 to avoid
// stale connCtx lookups when CLIENT pair creation is delayed (response >256
// bytes causes framing failure → pair created later after connCtx overwrite).
type causalCtxSnapshot struct {
	TraceID      string
	ServerSpanID string
}

// causalCtxQueue is a FIFO queue of context snapshots for an outbound FD.
// Parallel to the reassembly's causalFDQueue — both pushed in OnDataOut,
// popped at pair creation / enrichPairContext time.
type causalCtxQueue struct {
	mu      sync.Mutex
	entries []causalCtxSnapshot
}

func (q *causalCtxQueue) push(snap causalCtxSnapshot) {
	q.mu.Lock()
	q.entries = append(q.entries, snap)
	q.mu.Unlock()
}

func (q *causalCtxQueue) pop() (causalCtxSnapshot, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.entries) == 0 {
		return causalCtxSnapshot{}, false
	}
	snap := q.entries[0]
	q.entries = q.entries[1:]
	return snap, true
}

// pidInboundEntry tracks a single active inbound FD with its creation timestamp.
type pidInboundEntry struct {
	FD      int32
	Created time.Time
}

// pidInboundSet is a fixed-size ring buffer tracking all active inbound FDs
// for a single PID. Under concurrent requests, multiple inbound FDs may be
// active simultaneously. BestMatch uses a temporal heuristic to pick the FD
// whose creation time is closest to (but before) the query time.
type pidInboundSet struct {
	mu      sync.Mutex
	entries [16]pidInboundEntry
	count   int
}

// Add registers an inbound FD. If the FD already exists, its timestamp is
// updated. If the ring is full, the oldest entry is evicted.
func (s *pidInboundSet) Add(fd int32, t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Update existing entry if FD is reused
	for i := 0; i < s.count; i++ {
		if s.entries[i].FD == fd {
			s.entries[i].Created = t
			return
		}
	}
	if s.count < len(s.entries) {
		s.entries[s.count] = pidInboundEntry{FD: fd, Created: t}
		s.count++
	} else {
		// Evict oldest entry
		oldest := 0
		for i := 1; i < s.count; i++ {
			if s.entries[i].Created.Before(s.entries[oldest].Created) {
				oldest = i
			}
		}
		s.entries[oldest] = pidInboundEntry{FD: fd, Created: t}
	}
}

// Remove removes an inbound FD from the set.
func (s *pidInboundSet) Remove(fd int32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < s.count; i++ {
		if s.entries[i].FD == fd {
			s.entries[i] = s.entries[s.count-1]
			s.count--
			return
		}
	}
}

// BestMatch returns the inbound FD whose creation time is closest to (but
// not after) the query time. With a single entry this is O(1). With multiple
// entries it picks the most recently created FD that predates the query.
func (s *pidInboundSet) BestMatch(queryTime time.Time) (int32, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.count == 0 {
		return 0, false
	}
	if s.count == 1 {
		return s.entries[0].FD, true
	}
	// Find closest FD created at or before queryTime
	bestIdx := -1
	for i := 0; i < s.count; i++ {
		if !s.entries[i].Created.After(queryTime) {
			if bestIdx == -1 || s.entries[i].Created.After(s.entries[bestIdx].Created) {
				bestIdx = i
			}
		}
	}
	if bestIdx >= 0 {
		return s.entries[bestIdx].FD, true
	}
	// All entries are after queryTime (clock skew): pick closest regardless
	bestIdx = 0
	for i := 1; i < s.count; i++ {
		if s.entries[i].Created.Before(s.entries[bestIdx].Created) {
			bestIdx = i
		}
	}
	return s.entries[bestIdx].FD, true
}

// CleanStale removes entries older than maxAge.
func (s *pidInboundSet) CleanStale(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	i := 0
	for i < s.count {
		if s.entries[i].Created.Before(cutoff) {
			s.entries[i] = s.entries[s.count-1]
			s.count--
		} else {
			i++
		}
	}
}

// Count returns the number of active entries.
func (s *pidInboundSet) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
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

	// Initialize configurable max request duration
	a.maxRequestDuration = cfg.Tracing.MaxRequestDuration
	if a.maxRequestDuration == 0 {
		a.maxRequestDuration = 5 * time.Minute
	}

	// Initialize trace processor
	a.traceProc = traces.NewProcessor(logger)

	// Initialize cross-service trace stitcher
	stitchWindow := cfg.Tracing.StitchWindow
	if stitchWindow == 0 {
		stitchWindow = 2 * time.Second
	}
	a.traceStitcher = traces.NewStitcher(stitchWindow, logger)

	// Initialize correlation engine
	a.correlation = correlation.NewEngine(cfg.Correlation.Window, logger)

	// Initialize export manager
	serviceName := cfg.ServiceName
	if serviceName == "auto" || serviceName == "" {
		serviceName = "olly-agent"
	}

	exporter, err := export.NewManagerFromConfig(&export.ManagerConfig{
		Exporters:      &cfg.Exporters,
		ServiceName:    serviceName,
		ServiceVersion: cfg.ServiceVersion,
		DeploymentEnv:  cfg.DeploymentEnv,
		PyroscopeCfg:   &cfg.Profiling.Pyroscope,
	}, logger)
	if err != nil {
		return nil, fmt.Errorf("create exporter: %w", err)
	}
	a.exporter = exporter

	// Wire up late TraceMerge resolution at export flush time.
	// Internal spans (e.g., pricing CLIENT→stock) may reach the export
	// batch before the stitcher creates the TraceMerge entry for their trace.
	a.exporter.TraceMergeResolver = a.traceStitcher.TraceMerge

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

		// Request RED metrics (gated by config toggle)
		if cfg.Metrics.Request.Enabled {
			a.requestMetrics = rmetrics.NewRequestMetrics(cfg.Metrics.Request.Buckets)
		}

		// GenAI token/duration metrics
		if cfg.Metrics.GenAI.Enabled {
			gm := rmetrics.NewGenAIMetrics(cfg.Metrics.GenAI.Buckets)
			a.genaiMetrics.Store(gm)
		}

		// MCP tool call/duration metrics
		if cfg.Metrics.MCP.Enabled {
			mm := rmetrics.NewMCPMetrics(cfg.Metrics.MCP.Buckets)
			a.mcpMetrics.Store(mm)
		}

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

	// Compile trace filter maps from config
	a.buildFilterMaps(cfg)

	// Select hook provider: eBPF on Linux 5.8+, stub otherwise
	if cfg.Hook.Enabled {
		a.hookProvider = selectHookProvider(cfg, logger)
	}

	return a, nil
}

// selectHookProvider picks the best available hook provider for the platform.
func selectHookProvider(cfg *config.Config, logger *zap.Logger) hook.HookProvider {
	// Try eBPF (Linux 5.8+ with BTF)
	support := hookebpf.Detect()
	if support.Available {
		logger.Info("eBPF support detected",
			zap.String("kernel", support.KernelVersion),
			zap.Bool("btf", support.HasBTF),
		)
		return hookebpf.NewProvider(cfg, logger)
	}

	logger.Info("eBPF not available, using stub provider",
		zap.String("reason", support.Reason),
	)

	// Stub provider — agent runs without hook tracing (logs+metrics still work)
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
				// SSL uprobe events bypass BPF conn_map check, so the connect
				// kprobe may not have registered this connection (e.g., sockaddr
				// unreadable in kretprobe). Auto-register as outbound SSL.
				// kprobe DATA events always require conn_map, so they can't
				// reach here without a prior connect event.
				conn = a.connTracker.Register(pid, fd, 0, 443)
				conn.IsSSL = true
			} else if !conn.IsSSL {
				// Mark existing connection as SSL if plaintext looks like HTTP
				// over a port-443 connection (SSL uprobe data arriving for a
				// connection that was registered by the connect kprobe).
				if conn.RemotePort == 443 {
					conn.IsSSL = true
				}
			}

			// Connection-level filter: skip excluded addresses for OUTBOUND only.
			// Inbound connections may have addr=0 when accept(addr=NULL) is used
			// (Node.js/libuv pattern) — these are valid SERVER connections.
			remoteAddr := conn.RemoteAddrStr()
			if conn.Direction != conntrack.ConnInbound && a.excludedAddrs[remoteAddr] {
				return
			}

			a.connTracker.AddBytesSent(pid, fd, uint64(len(data)))

			remotePort := conn.RemotePort
			// For inbound (server) connections, outgoing data is the response.
			// Swap to keep sendBuf=request, recvBuf=response in the reassembler.
			if conn.Direction == conntrack.ConnInbound {
				a.reassembler.AppendRecv(pid, tid, fd, data, remoteAddr, remotePort, conn.IsSSL)
				a.reassembler.SetDirection(pid, fd, 1) // 1=inbound
			} else {
				// Record causal mapping: this outbound write was caused by
				// whichever inbound FD this thread is currently serving.
				// Push to FIFO queue BEFORE AppendSend so pipelined protocols
				// (Redis, HTTP keep-alive) get per-request causal tracking
				// instead of last-writer-wins on the fdCausal map.
				tidKey := uint64(pid)<<32 | uint64(tid)
				if inboundFD, ok := a.threadInboundFD.Load(tidKey); ok {
					iFD := inboundFD.(int32)
					a.reassembler.PushCausalFD(pid, fd, iFD)
					causalKey := uint64(pid)<<32 | uint64(uint32(fd))
					a.fdCausal.Store(causalKey, &causalEntry{
						InboundFD: iFD,
						Timestamp: time.Now(),
					})
					// Snapshot the inbound FD's trace context now. If the
					// CLIENT pair is created late (response >256 bytes),
					// connCtx may be overwritten by the next inbound request.
					// The snapshot preserves the correct TraceID/ServerSpanID.
					inboundKey := uint64(pid)<<32 | uint64(uint32(iFD))
					if ctxVal, ctxOK := a.connCtx.Load(inboundKey); ctxOK {
						tctx := ctxVal.(*connTraceCtx)
						outKey := uint64(pid)<<32 | uint64(uint32(fd))
						qVal, _ := a.causalCtxSnap.LoadOrStore(outKey, &causalCtxQueue{})
						qVal.(*causalCtxQueue).push(causalCtxSnapshot{
							TraceID:      tctx.TraceID,
							ServerSpanID: tctx.ServerSpanID,
						})
					}
				} else if val, ok := a.pidActiveCtx.Load(pid); ok {
					// PID-level fallback: Go goroutine TID mismatch.
					// threadInboundFD has no entry for this TID, but
					// pidActiveCtx tracks active inbound FDs.
					if bestFD, found := val.(*pidInboundSet).BestMatch(time.Now()); found {
						a.reassembler.PushCausalFD(pid, fd, bestFD)
					}
				}
				a.reassembler.AppendSend(pid, tid, fd, data, remoteAddr, remotePort, conn.IsSSL)
			}
		},

		OnDataIn: func(pid, tid uint32, fd int32, data []byte, ts uint64) {
			conn := a.connTracker.Lookup(pid, fd)
			if conn == nil {
				// SSL uprobe events bypass BPF conn_map — auto-register.
				conn = a.connTracker.Register(pid, fd, 0, 443)
				conn.IsSSL = true
			} else if !conn.IsSSL && conn.RemotePort == 443 {
				conn.IsSSL = true
			}

			// Connection-level filter: skip excluded addresses for OUTBOUND only.
			remoteAddr := conn.RemoteAddrStr()
			if conn.Direction != conntrack.ConnInbound && a.excludedAddrs[remoteAddr] {
				return
			}

			a.connTracker.AddBytesRecv(pid, fd, uint64(len(data)))

			remotePort := conn.RemotePort
			// For inbound (server) connections, incoming data is the request.
			// Swap to keep sendBuf=request, recvBuf=response in the reassembler.
			if conn.Direction == conntrack.ConnInbound {
				// Store trace context keyed by FD (connection-scoped).
				// FD-keyed context survives goroutine migration and handles
				// concurrent requests correctly (each connection has its own context).
				connKey := uint64(pid)<<32 | uint64(uint32(fd))

				// Track which inbound FD this thread is serving (for causal mapping)
				tidKey := uint64(pid)<<32 | uint64(tid)
				a.threadInboundFD.Store(tidKey, fd)

				// Update PID-level multi-entry tracking (handles concurrent inbound)
				{
					val, _ := a.pidActiveCtx.LoadOrStore(pid, &pidInboundSet{})
					val.(*pidInboundSet).Add(fd, time.Now())
				}

				{
					tctx := &connTraceCtx{Created: time.Now()}

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

					// Priority 2: Check event-embedded BPF trace context (race-free).
					// BPF embeds trace context directly in the ring buffer event,
					// eliminating the map read race where BPF overwrites before Go reads.
					// Always read BPF SpanID: sk_msg uses BPF's thread_trace_ctx to
					// inject traceparent into outbound HTTP. The CLIENT span's SpanID
					// must match what BPF injects, so downstream SERVERs reference
					// the correct parent. TraceID only used if Priority 1 didn't set it.
					var bpfEventTraceID string
					if etp, ok := a.hookProvider.(hook.EventTraceProvider); ok {
						if evtTraceID, evtSpanID, evtOK := etp.GetEventTraceContext(pid, tid); evtOK {
							bpfEventTraceID = evtTraceID
							if tctx.TraceID == "" {
								tctx.TraceID = evtTraceID
							}
							tctx.SpanID = evtSpanID
							a.logger.Debug("using event-embedded BPF trace context",
								zap.Uint32("pid", pid), zap.Uint32("tid", tid),
								zap.String("traceID", tctx.TraceID),
								zap.String("bpfSpanID", evtSpanID))
						}
					}

					// Priority 3: Fall back to BPF map read (backward compat).
					// Only used if event-embedded context is not available.
					if tctx.TraceID == "" || tctx.SpanID == "" {
						if injector, ok := a.hookProvider.(hook.TraceInjector); ok {
							if bpfTraceID, bpfSpanID, bpfOK := injector.GetTraceContext(pid, tid); bpfOK {
								if tctx.TraceID == "" {
									tctx.TraceID = bpfTraceID
								}
								if tctx.SpanID == "" {
									tctx.SpanID = bpfSpanID
								}
								a.logger.Debug("using BPF map trace context (fallback)",
									zap.Uint32("pid", pid), zap.Uint32("tid", tid),
									zap.String("traceID", tctx.TraceID))
							}
						}
					}

					// Priority 4: Generate new trace ID
					if tctx.TraceID == "" {
						tctx.TraceID = traces.GenerateTraceID()
					}
					if tctx.SpanID == "" {
						tctx.SpanID = traces.GenerateSpanID()
					}
					// BPF traceID → canonical traceID merge.
					// BPF kretprobe_read generates a fresh traceID at each service hop.
					// sk_msg injects this BPF traceID into outbound HTTP connections.
					// But the Go agent knows the correct traceID from the extracted
					// upstream traceparent (Priority 1). When these differ, register a
					// merge so downstream spans (arriving with the BPF traceID via
					// sk_msg injection) get redirected to the canonical trace.
					if traceCtx.TraceID != "" && bpfEventTraceID != "" && traceCtx.TraceID != bpfEventTraceID {
						canonical := tctx.TraceID
						if a.traceStitcher != nil {
							if resolved, ok := a.traceStitcher.TraceMerge(canonical); ok {
								canonical = resolved
							}
							a.traceStitcher.AddTraceMerge(bpfEventTraceID, canonical)
							a.logger.Debug("registered BPF→canonical trace merge",
								zap.String("bpfTraceID", bpfEventTraceID),
								zap.String("canonical", canonical))
						}
						tctx.TraceID = canonical
					}

					tctx.ServerSpanID = traces.GenerateSpanID()
					tctx.ReadTID = tid
					a.connCtx.Store(connKey, tctx)

					// Early registration: make trace context available for log
					// correlation BEFORE the app writes any logs during request
					// processing. Without this, logs are exported without trace
					// context because spans complete after log writes.
					if a.correlation != nil {
						svcName := ""
						if a.discoverer != nil {
							svcName = a.discoverer.GetServiceName(pid)
						}
						a.correlation.RegisterSpanStart(pid, tid, tctx.TraceID, tctx.ServerSpanID, tctx.ParentSpanID, svcName, "", time.Now())
					}
				}
				a.reassembler.AppendSend(pid, tid, fd, data, remoteAddr, remotePort, conn.IsSSL)
				a.reassembler.SetDirection(pid, fd, 1) // 1=inbound; set after AppendSend creates the stream
			} else {
				a.reassembler.AppendRecv(pid, tid, fd, data, remoteAddr, remotePort, conn.IsSSL)
			}
		},

		OnClose: func(pid, tid uint32, fd int32, ts uint64) {
			a.reassembler.RemoveStream(pid, fd, tid)
			// Clean up fdCausal and connTracker, but NOT connCtx.
			// connCtx must survive briefly after close so that outbound
			// CLIENT pairs still in flight can look up the inbound trace
			// context via enrichPairContext Layer 3 (pidActiveCtx → connCtx).
			// The maxRequestDuration stale check in enrichPairContext prevents using
			// truly old context, and FD reuse naturally overwrites entries.
			connKey := uint64(pid)<<32 | uint64(uint32(fd))
			a.fdCausal.Delete(connKey)
			a.causalCtxSnap.Delete(connKey)
			// Do NOT remove from pidActiveCtx here — connCtx must survive
			// briefly after close so that outbound CLIENT pairs still in
			// flight can look up the inbound trace context via Layer 3.
			// CleanStale handles purging old entries.
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
		// OnDataIn creates connCtx in this same goroutine, so the context
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

	// Register stitcher callback to re-export counterpart spans.
	// When the stitcher matches a CLIENT↔SERVER pair asynchronously (the
	// counterpart arrived after the first span was already exported), the
	// updated clone must be re-exported so Grafana sees both spans in the
	// same trace with proper parent links.
	if a.traceStitcher != nil {
		a.traceStitcher.OnStitchedSpan(func(span *traces.Span) {
			// Resolve stale traceIDs: deferred spans may have been stored before
			// a TraceMerge entry was created by a later stitch on the same service.
			if newTraceID, ok := a.traceStitcher.TraceMerge(span.TraceID); ok {
				span.TraceID = newTraceID
			}
			// Enrich with service name (clone may not have it yet)
			if a.discoverer != nil && span.ServiceName == "" {
				span.ServiceName = a.discoverer.GetServiceName(span.PID)
			}
			a.exporter.ExportSpan(span)
		})
	}

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
			em := &export.Metric{
				Name:        m.Name,
				Description: m.Description,
				Unit:        m.Unit,
				Type:        export.MetricType(m.Type),
				Value:       m.Value,
				Timestamp:   m.Timestamp,
				StartTime:   m.StartTime,
				Labels:      m.Labels,
				ServiceName: m.ServiceName,
			}
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
			em := &export.Metric{
				Name:        m.Name,
				Description: m.Description,
				Unit:        m.Unit,
				Type:        export.MetricType(m.Type),
				Value:       m.Value,
				Timestamp:   m.Timestamp,
				StartTime:   m.StartTime,
				Labels:      m.Labels,
				ServiceName: m.ServiceName,
			}
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
		})
		if err := a.processColl.Start(ctx, cfg.Metrics.Interval); err != nil {
			a.logger.Warn("process metrics start error", zap.Error(err))
		}
	}

	// Start container metrics
	if a.containerColl != nil {
		a.containerColl.OnMetric(func(m *metrics.Metric) {
			em := &export.Metric{
				Name:        m.Name,
				Description: m.Description,
				Unit:        m.Unit,
				Type:        export.MetricType(m.Type),
				Value:       m.Value,
				Timestamp:   m.Timestamp,
				StartTime:   m.StartTime,
				Labels:      m.Labels,
				ServiceName: m.ServiceName,
			}
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

			// Populate ephemeral port for outbound connections (lazy BPF map lookup).
			// By pairDispatchLoop time, sockops has always fired (TCP established before data sent).
			if pair.Direction == 0 && pair.LocalPort == 0 {
				if epp, ok := a.hookProvider.(hook.EphemeralPortProvider); ok {
					var remoteAddr uint32
					if connInfo != nil {
						remoteAddr = connInfo.RemoteAddr
					}
					if lp, cookie, found := epp.GetEphemeralPort(pair.PID, remoteAddr, pair.RemotePort); found {
						pair.LocalPort = lp
						if connInfo != nil {
							connInfo.LocalPort = lp
							connInfo.SocketCookie = cookie
						}
					}
				}
			}

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
	connInfo := a.connTracker.Lookup(pair.PID, pair.FD)

	// SERVER pairs: direct lookup by the pair's own FD (which IS the inbound FD).
	if connInfo != nil && connInfo.Direction == conntrack.ConnInbound {
		connKey := uint64(pair.PID)<<32 | uint64(uint32(pair.FD))
		val, ok := a.connCtx.Load(connKey)
		if !ok {
			return
		}
		tctx, ok := val.(*connTraceCtx)
		if !ok || time.Since(tctx.Created) > a.maxRequestDuration {
			return
		}
		pair.ParentTraceID = tctx.TraceID
		pair.ParentSpanID = tctx.ServerSpanID
		// Clear BPF trace context since sk_msg injection already happened.
		if injector, ok := a.hookProvider.(hook.TraceInjector); ok {
			injector.ClearTraceContext(pair.PID, pair.TID)
		}
		return
	}

	// CLIENT pairs: 4-layer FD-based lookup to find the inbound context
	// that caused this outbound request.
	var inboundFD int32
	var found bool

	// Layer 0: Per-request causal FD from FIFO queue (most accurate for
	// pipelined protocols). Captured at AppendSend time, before concurrent
	// requests can overwrite the fdCausal map. Handles Redis, HTTP keep-alive,
	// and other persistent-connection protocols correctly.
	//
	// Also pop the context snapshot (captured at PushCausalFD time in OnDataOut).
	// If the CLIENT pair was created late (response >256 bytes, framing delay),
	// connCtx may have been overwritten by a new inbound request on the same FD.
	// The snapshot preserves the TraceID/ServerSpanID from the original request.
	var causalSnap *causalCtxSnapshot
	if pair.CausalInboundFD != 0 {
		inboundFD = pair.CausalInboundFD
		found = true
		// Pop context snapshot parallel to the reassembly's causalFDQueue pop.
		outKey := uint64(pair.PID)<<32 | uint64(uint32(pair.FD))
		if qVal, ok := a.causalCtxSnap.Load(outKey); ok {
			if snap, ok := qVal.(*causalCtxQueue).pop(); ok {
				causalSnap = &snap
			}
		}
	}

	// Layer 1: FD causal mapping (fallback when queue wasn't populated).
	// OnDataOut recorded which inbound FD caused this outbound write.
	if !found {
		causalKey := uint64(pair.PID)<<32 | uint64(uint32(pair.FD))
		if val, ok := a.fdCausal.Load(causalKey); ok {
			ce := val.(*causalEntry)
			if time.Since(ce.Timestamp) <= a.maxRequestDuration {
				// Verify the causal entry is from the CURRENT request on that
				// inbound FD. Persistent connections (Redis, pooled HTTP) reuse
				// FDs across requests: a stale causal entry from a previous
				// request would map to the wrong connCtx (overwritten by the
				// new request). Skip to Layer 2/3 if the connCtx is newer.
				inboundKey := uint64(pair.PID)<<32 | uint64(uint32(ce.InboundFD))
				if ctxVal, ctxOK := a.connCtx.Load(inboundKey); ctxOK {
					tctx := ctxVal.(*connTraceCtx)
					if !ce.Timestamp.Before(tctx.Created) {
						inboundFD = ce.InboundFD
						found = true
					}
				}
				// If connCtx doesn't exist or is newer than the causal entry,
				// fall through to Layer 2/3.
			}
		}
	}

	// Layer 2: Thread → inbound FD mapping (fallback for first write).
	if !found {
		tidKey := uint64(pair.PID)<<32 | uint64(pair.TID)
		if val, ok := a.threadInboundFD.Load(tidKey); ok {
			inboundFD = val.(int32)
			found = true
		}
	}

	// Layer 3: PID-level temporal match (handles concurrent inbound FDs).
	// Uses BestMatch to pick the inbound FD whose creation time is closest
	// to the pair's request time, fixing the single-FD overwrite bug.
	if !found {
		if val, ok := a.pidActiveCtx.Load(pair.PID); ok {
			if bestFD, matched := val.(*pidInboundSet).BestMatch(pair.RequestTime); matched {
				inboundFD = bestFD
				found = true
			}
		}
	}

	if !found {
		return
	}

	// Resolve inbound FD → connection trace context
	connKey := uint64(pair.PID)<<32 | uint64(uint32(inboundFD))
	val, ok := a.connCtx.Load(connKey)
	if !ok {
		// connCtx was removed — use snapshot if available.
		if causalSnap != nil && causalSnap.TraceID != "" {
			pair.ParentTraceID = causalSnap.TraceID
			pair.ParentSpanID = causalSnap.ServerSpanID
		}
		return
	}
	tctx, ok := val.(*connTraceCtx)
	if !ok || time.Since(tctx.Created) > a.maxRequestDuration {
		return
	}

	// Check if connCtx was overwritten by a newer request (delayed pair
	// creation: response >256 bytes caused framing failure, pair created
	// after next inbound request overwrote connCtx). Use snapshot to
	// preserve the correct TraceID/ServerSpanID from the original request.
	if causalSnap != nil && causalSnap.TraceID != "" && causalSnap.TraceID != tctx.TraceID {
		// connCtx was overwritten — use snapshot for TraceID/ServerSpanID.
		// Don't set InjectedSpanID since we can't reliably consume from
		// the wrong connCtx. The CLIENT span gets a generated SpanID and
		// falls back to stitcher for CLIENT↔SERVER linking.
		pair.ParentTraceID = causalSnap.TraceID
		pair.ParentSpanID = causalSnap.ServerSpanID
		return
	}

	pair.ParentTraceID = tctx.TraceID
	pair.ParentSpanID = tctx.ServerSpanID

	// Outbound CLIENT span: pass the sk_msg-injected spanID so the
	// CLIENT span uses it as its own spanID (matching what downstream sees).
	// Only for HTTP/gRPC: sk_msg only injects traceparent into HTTP traffic.
	//
	// Two paths for InjectedSpanID:
	// 1. TID match: outbound write is on the same OS thread as inbound read.
	//    sk_msg finds thread_trace_ctx[PID+TID] directly. Always correct.
	// 2. TID mismatch (Go goroutine migration): BPF's maybe_forward_trace_ctx
	//    copies pid_trace_ctx[PID] → thread_trace_ctx[PID+write_TID] in
	//    kprobe_write, enabling sk_msg injection even across thread migration.
	//    The BPF concurrency guard prevents wrong injection when multiple
	//    inbound requests are active. Under concurrency, sk_msg won't inject
	//    and these spans fall back to the stitcher.
	if pair.Protocol == "http" || pair.Protocol == "grpc" || pair.Protocol == "genai" || pair.Protocol == "mcp" {
		if tctx.ReadTID != 0 {
			pair.InjectedSpanID = tctx.SpanID
		}
		// Consume: generate a new SpanID for subsequent CLIENT spans on
		// this connection. Without this, multiple outbound calls reusing
		// the same FD would all get the same SpanID.
		tctx.SpanID = traces.GenerateSpanID()
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

	// Span-level filter: service whitelist, path exclusion, protocol toggle
	if a.shouldFilterSpan(span) {
		a.healthStats.SpansDropped.Add(1)
		return
	}

	// Apply PII redaction to sensitive attributes
	a.redactor.RedactMap(span.Attributes, "db.query.text", "http.request.header.authorization", "url.query")

	// Normalize SQL queries
	if stmt, ok := span.Attributes["db.query.text"]; ok && stmt != "" {
		span.Attributes["db.query.text"] = redact.NormalizeSQL(stmt)
	}

	// Apply trace merge: when stitching changed a SERVER's traceID to match
	// a CLIENT's trace, propagate the change to future spans from the same
	// downstream process (e.g., Java CLIENT → .NET spans get the correct
	// traceID if they arrive after the stitch).
	if a.traceStitcher != nil {
		if newTraceID, ok := a.traceStitcher.TraceMerge(span.TraceID); ok {
			span.TraceID = newTraceID
		}
	}

	// Cross-service trace stitching: CLIENT spans may be deferred (stored
	// for future matching). Deferred spans are NOT exported here — the
	// stitcher will re-export them via OnStitchedSpan when matched, or
	// export them when they expire unmatched in Cleanup.
	if a.traceStitcher != nil {
		if a.traceStitcher.ProcessSpan(span) {
			// Span was deferred by the stitcher — skip export.
			return
		}
	}

	// Register with correlation engine
	if a.correlation != nil {
		a.correlation.RegisterSpanStart(
			span.PID, span.TID,
			span.TraceID, span.SpanID, span.ParentSpanID,
			span.ServiceName, span.Name,
			span.StartTime,
		)
	}

	// Record request metrics
	if a.requestMetrics != nil {
		a.requestMetrics.RecordSpan(span)
	}

	// Record GenAI metrics (B2 fix: atomic load prevents race with Reload)
	if gm := a.genaiMetrics.Load(); gm != nil {
		gm.RecordSpan(span)
	}

	// Record MCP metrics
	if mm := a.mcpMetrics.Load(); mm != nil {
		mm.RecordSpan(span)
	}

	// Feed CLIENT spans to service map for enrichment
	if a.serviceMap != nil && span.Kind == traces.SpanKindClient {
		srcService := span.ServiceName
		dstService := span.RemoteAddr
		if a.discoverer != nil {
			if portName := a.discoverer.GetServiceNameByPort(span.RemotePort); portName != "" {
				dstService = portName
			}
		}
		a.serviceMap.RecordSpan(
			srcService, dstService, span.RemotePort,
			span.Protocol, span.Status == traces.StatusError,
			span.Duration,
		)
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

// processHookLog handles log data captured by the write() kprobe in eBPF.
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

	// Update configurable trace context lifetime
	a.maxRequestDuration = cfg.Tracing.MaxRequestDuration
	if a.maxRequestDuration == 0 {
		a.maxRequestDuration = 5 * time.Minute
	}

	// Recompile trace filter maps
	a.buildFilterMaps(cfg)

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
	if cfg.Metrics.Request.Enabled {
		a.requestMetrics = rmetrics.NewRequestMetrics(cfg.Metrics.Request.Buckets)
	}
	if cfg.Metrics.GenAI.Enabled {
		gm := rmetrics.NewGenAIMetrics(cfg.Metrics.GenAI.Buckets)
		a.genaiMetrics.Store(gm)
	}
	if cfg.Metrics.MCP.Enabled {
		mm := rmetrics.NewMCPMetrics(cfg.Metrics.MCP.Buckets)
		a.mcpMetrics.Store(mm)
	}
	a.metricsColl.OnMetric(func(m *metrics.Metric) {
		em := &export.Metric{
			Name:        m.Name,
			Description: m.Description,
			Unit:        m.Unit,
			Type:        export.MetricType(m.Type),
			Value:       m.Value,
			Timestamp:   m.Timestamp,
			StartTime:   m.StartTime,
			Labels:      m.Labels,
			ServiceName: m.ServiceName,
		}
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
	a.genaiMetrics.Store(nil)
	a.mcpMetrics.Store(nil)
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

	// Fast stitcher cleanup: SERVER spans are deferred (not exported until
	// matched or expired). Run Cleanup every 2s so unmatched SERVER spans
	// are exported within ~2s instead of waiting for the 30s main ticker.
	stitchTicker := time.NewTicker(2 * time.Second)
	defer stitchTicker.Stop()

	for {
		select {
		case <-stitchTicker.C:
			if a.traceStitcher != nil {
				a.traceStitcher.Cleanup()
			}

		case <-ticker.C:
			// Clean stale connections and streams. Use 30s for streams so
			// SSL connections (no BPF CLOSE events) emit pairs promptly.
			staleConns := a.connTracker.CleanStale(5 * time.Minute)
			staleStreams := a.reassembler.CleanStale(30 * time.Second)

			// Clean stale stitching entries (also handled by fast ticker above,
			// but included here for the log message)
			staleStitched := 0
			if a.traceStitcher != nil {
				staleStitched = a.traceStitcher.Cleanup()
			}

			// Clean stale connection trace contexts
			staleConnCtx := 0
			a.connCtx.Range(func(key, value any) bool {
				tctx, ok := value.(*connTraceCtx)
				if !ok {
					a.connCtx.Delete(key)
					return true
				}
				if time.Since(tctx.Created) > a.maxRequestDuration {
					a.connCtx.Delete(key)
					staleConnCtx++
				}
				return true
			})

			// Clean stale causal entries
			a.fdCausal.Range(func(key, value any) bool {
				ce, ok := value.(*causalEntry)
				if !ok || time.Since(ce.Timestamp) > a.maxRequestDuration {
					a.fdCausal.Delete(key)
				}
				return true
			})

			// Clean stale threadInboundFD entries (whose connCtx no longer exists)
			a.threadInboundFD.Range(func(key, value any) bool {
				fd, ok := value.(int32)
				if !ok {
					a.threadInboundFD.Delete(key)
					return true
				}
				k, ok := key.(uint64)
				if !ok {
					a.threadInboundFD.Delete(key)
					return true
				}
				pid := uint32(k >> 32)
				connKey := uint64(pid)<<32 | uint64(uint32(fd))
				if _, exists := a.connCtx.Load(connKey); !exists {
					a.threadInboundFD.Delete(key)
					// Clear leaked BPF map entry
					if injector, ok := a.hookProvider.(hook.TraceInjector); ok {
						tid := uint32(k & 0xFFFFFFFF)
						injector.ClearTraceContext(pid, tid)
					}
				}
				return true
			})

			// Clean stale pidActiveCtx entries
			a.pidActiveCtx.Range(func(key, value any) bool {
				_, ok := key.(uint32)
				if !ok {
					a.pidActiveCtx.Delete(key)
					return true
				}
				set, ok := value.(*pidInboundSet)
				if !ok {
					a.pidActiveCtx.Delete(key)
					return true
				}
				set.CleanStale(a.maxRequestDuration)
				if set.Count() == 0 {
					a.pidActiveCtx.Delete(key)
				}
				return true
			})

			// Process auto-discovery: scan for matching processes
			cfg := a.cfg.Load()
			if a.discoverer != nil && len(cfg.Discovery.ProcessNames) > 0 && a.processColl != nil {
				discovered := a.discoverer.ScanProcesses(cfg.Discovery.ProcessNames)
				for _, pid := range discovered {
					a.processColl.AddPID(pid)
				}
			}

			if staleConns > 0 || staleStreams > 0 || staleStitched > 0 || staleConnCtx > 0 {
				a.logger.Debug("cleanup",
					zap.Int("stale_connections", staleConns),
					zap.Int("stale_streams", staleStreams),
					zap.Int("stale_stitched", staleStitched),
					zap.Int("stale_conn_ctx", staleConnCtx),
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

// exportMetricSlice converts and exports a slice of internal metrics.
func (a *Agent) exportMetricSlice(metrics []*metrics.Metric) {
	for _, m := range metrics {
		em := &export.Metric{
			Name:        m.Name,
			Description: m.Description,
			Unit:        m.Unit,
			Type:        export.MetricType(m.Type),
			Value:       m.Value,
			Timestamp:   m.Timestamp,
			StartTime:   m.StartTime,
			Labels:      m.Labels,
			ServiceName: m.ServiceName,
		}
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
}

// buildFilterMaps compiles filter config into maps for fast lookup.
func (a *Agent) buildFilterMaps(cfg *config.Config) {
	// Excluded addresses (connection-level)
	addrs := make(map[string]bool, len(cfg.Tracing.Filter.ExcludeAddresses))
	for _, addr := range cfg.Tracing.Filter.ExcludeAddresses {
		addrs[addr] = true
	}
	a.excludedAddrs = addrs

	// Include services whitelist (span-level)
	services := make(map[string]bool, len(cfg.Tracing.Filter.IncludeServices))
	for _, svc := range cfg.Tracing.Filter.IncludeServices {
		services[svc] = true
	}
	a.includeServices = services

	// Exclude paths (span-level)
	a.excludePaths = cfg.Tracing.Filter.ExcludePaths

	if len(addrs) > 0 || len(services) > 0 || len(a.excludePaths) > 0 {
		a.logger.Info("trace filters configured",
			zap.Int("exclude_addresses", len(addrs)),
			zap.Int("include_services", len(services)),
			zap.Int("exclude_paths", len(a.excludePaths)),
		)
	}
}

// shouldFilterSpan returns true if the span should be dropped based on filters.
func (a *Agent) shouldFilterSpan(span *traces.Span) bool {
	// Service whitelist: if configured, only allow listed services
	if len(a.includeServices) > 0 && span.ServiceName != "" {
		if !a.includeServices[span.ServiceName] {
			return true
		}
	}

	// Path exclusion: drop spans matching excluded URL path prefixes
	if urlPath, ok := span.Attributes["url.path"]; ok && len(a.excludePaths) > 0 {
		for _, prefix := range a.excludePaths {
			if strings.HasPrefix(urlPath, prefix) {
				return true
			}
		}
	}

	// Protocol toggle: drop spans for disabled protocols
	if !a.isProtocolEnabled(span.Protocol) {
		return true
	}

	return false
}

// isProtocolEnabled checks whether the given protocol is enabled in config.
func (a *Agent) isProtocolEnabled(proto string) bool {
	cfg := a.cfg.Load()
	switch proto {
	case "http":
		return cfg.Tracing.Protocols.HTTP.Enabled
	case "grpc":
		return cfg.Tracing.Protocols.GRPC.Enabled
	case "postgres":
		return cfg.Tracing.Protocols.Postgres.Enabled
	case "mysql":
		return cfg.Tracing.Protocols.MySQL.Enabled
	case "redis":
		return cfg.Tracing.Protocols.Redis.Enabled
	case "mongodb":
		return cfg.Tracing.Protocols.MongoDB.Enabled
	case "dns":
		return cfg.Tracing.Protocols.DNS.Enabled
	case "genai":
		return cfg.Tracing.Protocols.GenAI.Enabled
	case "mcp":
		return cfg.Tracing.Protocols.MCP.Enabled
	default:
		return true // unknown protocols pass through
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
			a.exportMetricSlice(a.requestMetrics.Collect(now))
			if gm := a.genaiMetrics.Load(); gm != nil {
				a.exportMetricSlice(gm.Collect(now))
			}
			if mm := a.mcpMetrics.Load(); mm != nil {
				a.exportMetricSlice(mm.Collect(now))
			}

		case <-ctx.Done():
			return
		}
	}
}
