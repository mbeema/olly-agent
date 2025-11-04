package ebpf

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/hook"
	"go.uber.org/zap"
)

// Provider implements hook.HookProvider using eBPF kprobes and ring buffers.
// It attaches to kernel syscall entry/exit points to observe all network I/O
// without requiring LD_PRELOAD or process modification.
//
// It also optionally implements hook.TraceInjector for injecting traceparent
// headers into outbound HTTP requests via sockops + sk_msg BPF programs.
type Provider struct {
	cfg    *config.Config
	logger *zap.Logger

	loader      *loader
	eventReader *eventReader
	sslScanner  *sslScanner

	// Whether traceparent injection is active
	injectionActive bool

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

var _ hook.HookProvider = (*Provider)(nil)
var _ hook.TraceInjector = (*Provider)(nil)

// NewProvider creates a new eBPF hook provider. It does not load or attach
// BPF programs until Start() is called.
func NewProvider(cfg *config.Config, logger *zap.Logger) hook.HookProvider {
	return &Provider{
		cfg:    cfg,
		logger: logger,
	}
}

// Start loads eBPF programs, attaches probes, and begins reading events.
func (p *Provider) Start(ctx context.Context, callbacks hook.Callbacks) error {
	ctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel

	// Load BPF objects
	p.loader = newLoader(p.logger)
	if err := p.loader.load(); err != nil {
		cancel()
		return fmt.Errorf("load eBPF programs: %w", err)
	}

	// Attach syscall kprobes
	if err := p.loader.attachSyscallProbes(); err != nil {
		p.loader.close()
		cancel()
		return fmt.Errorf("attach syscall probes: %w", err)
	}

	// Attach tracepoints (non-fatal if fails)
	if err := p.loader.attachTracepoints(); err != nil {
		p.logger.Warn("tracepoint attach error", zap.Error(err))
	}

	// Create ring buffer reader
	var err error
	p.eventReader, err = newEventReader(p.loader.eventRingBuf(), callbacks, p.logger)
	if err != nil {
		p.loader.close()
		cancel()
		return fmt.Errorf("create event reader: %w", err)
	}

	// Start ring buffer reader goroutine
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.eventReader.readLoop()
	}()

	// Start SSL library scanner
	p.sslScanner = newSSLScanner(p.loader, p.logger)
	p.sslScanner.scanExistingProcesses()

	// Try to set up traceparent injection (sockops + sk_msg).
	// Non-fatal: falls back to cross-service trace stitching if this fails.
	p.setupTraceInjection()

	p.logger.Info("eBPF hook provider started",
		zap.Int("links", len(p.loader.links)),
		zap.Bool("injection", p.injectionActive),
	)

	return nil
}

// setupTraceInjection attaches sockops + sk_msg programs for automatic
// traceparent header injection into outbound HTTP requests.
func (p *Provider) setupTraceInjection() {
	// Find the root cgroup v2 mount point
	cgroupPath := findCgroupV2Path()
	if cgroupPath == "" {
		p.logger.Info("cgroup v2 not found, traceparent injection disabled (using trace stitching)")
		return
	}

	if err := p.loader.attachSockopsAndSkMsg(cgroupPath); err != nil {
		p.logger.Info("traceparent injection unavailable (using trace stitching)",
			zap.Error(err),
		)
		return
	}

	p.injectionActive = true
	p.logger.Info("traceparent injection enabled via sockops+sk_msg",
		zap.String("cgroup", cgroupPath),
	)
}

// findCgroupV2Path returns the root cgroup v2 mount point, typically
// /sys/fs/cgroup on modern systems. Returns empty string if not found.
func findCgroupV2Path() string {
	// Standard location for unified cgroup v2
	candidates := []string{
		"/sys/fs/cgroup",
		"/sys/fs/cgroup/unified",
	}
	for _, path := range candidates {
		info, err := os.Stat(path)
		if err == nil && info.IsDir() {
			return path
		}
	}
	return ""
}

// Stop detaches all probes and releases eBPF resources.
func (p *Provider) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}

	// Close the ring buffer reader first — this unblocks readLoop
	if p.eventReader != nil {
		p.eventReader.close()
	}

	// Wait for reader goroutine to exit
	p.wg.Wait()

	// Close SSL scanner
	if p.sslScanner != nil {
		p.sslScanner.close()
	}

	// Detach probes and close BPF objects
	if p.loader != nil {
		p.loader.close()
	}

	p.logger.Info("eBPF hook provider stopped")
	return nil
}

// EnableTracing sets the BPF tracing_enabled map to 1.
func (p *Provider) EnableTracing() error {
	if p.loader == nil {
		return fmt.Errorf("provider not started")
	}
	if err := p.loader.setTracingEnabled(true); err != nil {
		return fmt.Errorf("enable tracing: %w", err)
	}
	p.logger.Info("eBPF tracing enabled")
	return nil
}

// DisableTracing sets the BPF tracing_enabled map to 0.
func (p *Provider) DisableTracing() error {
	if p.loader == nil {
		return fmt.Errorf("provider not started")
	}
	if err := p.loader.setTracingEnabled(false); err != nil {
		return fmt.Errorf("disable tracing: %w", err)
	}
	p.logger.Info("eBPF tracing disabled")
	return nil
}

// IsTracingEnabled returns whether BPF tracing is active.
func (p *Provider) IsTracingEnabled() bool {
	if p.loader == nil {
		return false
	}
	return p.loader.isTracingEnabled()
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "ebpf"
}

// ──────────────────────────────────────────────────────────────────────
// TraceInjector interface implementation
// ──────────────────────────────────────────────────────────────────────

// SetTraceContext stores a pre-formatted traceparent header in the BPF map
// for the given PID+TID. When that thread sends an HTTP request, the sk_msg
// program injects the header automatically.
func (p *Provider) SetTraceContext(pid, tid uint32, traceID, spanID string) error {
	if !p.injectionActive || p.loader == nil {
		return nil // silently skip if injection not available
	}

	// Format: "traceparent: 00-{traceID}-{spanID}-01\r\n"
	header := "traceparent: 00-" + traceID + "-" + spanID + "-01\r\n"
	p.logger.Debug("SetTraceContext", zap.Uint32("pid", pid), zap.Uint32("tid", tid), zap.String("header", header[:len(header)-2]))
	return p.loader.setTraceContext(pid, tid, header)
}

// ClearTraceContext removes trace context for a PID+TID from the BPF map.
func (p *Provider) ClearTraceContext(pid, tid uint32) error {
	if !p.injectionActive || p.loader == nil {
		return nil
	}
	p.logger.Debug("ClearTraceContext", zap.Uint32("pid", pid), zap.Uint32("tid", tid))
	return p.loader.clearTraceContext(pid, tid)
}

// GetTraceContext reads the BPF-generated trace context for a PID+TID.
// The BPF kretprobe generates trace context synchronously when it detects
// an inbound HTTP request, so it's available before userspace processing.
func (p *Provider) GetTraceContext(pid, tid uint32) (traceID, spanID string, ok bool) {
	if !p.injectionActive || p.loader == nil {
		return "", "", false
	}
	return p.loader.getTraceContext(pid, tid)
}

// SupportsInjection returns whether sockops + sk_msg injection is active.
func (p *Provider) SupportsInjection() bool {
	return p.injectionActive
}
