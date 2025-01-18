package ebpf

import (
	"context"
	"fmt"
	"sync"

	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/hook"
	"go.uber.org/zap"
)

// Provider implements hook.HookProvider using eBPF kprobes and ring buffers.
// It attaches to kernel syscall entry/exit points to observe all network I/O
// without requiring LD_PRELOAD or process modification.
type Provider struct {
	cfg    *config.Config
	logger *zap.Logger

	loader      *loader
	eventReader *eventReader
	sslScanner  *sslScanner

	wg     sync.WaitGroup
	cancel context.CancelFunc
}

var _ hook.HookProvider = (*Provider)(nil)

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

	p.logger.Info("eBPF hook provider started",
		zap.Int("links", len(p.loader.links)),
	)

	return nil
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
