//go:build !linux

package profiling

import (
	"context"
)

// stubProfiler is a no-op profiler for non-Linux platforms.
type stubProfiler struct {
	cfg *Config
}

func newProfiler(cfg *Config) Profiler {
	return &stubProfiler{cfg: cfg}
}

func (p *stubProfiler) Start(ctx context.Context) error {
	if p.cfg.Logger != nil {
		p.cfg.Logger.Info("CPU profiling not available on this platform")
	}
	return nil
}

func (p *stubProfiler) Stop() error {
	return nil
}

func (p *stubProfiler) OnSample(fn func(*Sample)) {
	// No-op
}
