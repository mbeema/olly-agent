//go:build linux

package profiling

import (
	"context"
	"sync"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// linuxProfiler uses perf_event for CPU profiling on Linux.
type linuxProfiler struct {
	cfg       *Config
	logger    *zap.Logger
	mu        sync.RWMutex
	callbacks []func(*Sample)
	wg        sync.WaitGroup
	stopCh    chan struct{}
	perfFDs   []int
}

func newProfiler(cfg *Config) Profiler {
	return &linuxProfiler{
		cfg:    cfg,
		logger: cfg.Logger,
		stopCh: make(chan struct{}),
	}
}

func (p *linuxProfiler) OnSample(fn func(*Sample)) {
	p.mu.Lock()
	p.callbacks = append(p.callbacks, fn)
	p.mu.Unlock()
}

func (p *linuxProfiler) Start(ctx context.Context) error {
	// Open perf_event for CPU sampling
	attr := &unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Size:   uint32(unsafe_Sizeof_PerfEventAttr()),
		Bits:   unix.PerfBitFreq,
		Sample: uint64(p.cfg.SampleRate),
	}
	attr.Sample_type = unix.PERF_SAMPLE_IP | unix.PERF_SAMPLE_TID | unix.PERF_SAMPLE_CALLCHAIN

	// Open on all CPUs for pid -1 (all processes)
	fd, err := unix.PerfEventOpen(attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		p.logger.Warn("perf_event_open failed (requires CAP_PERFMON or root)", zap.Error(err))
		return nil // Non-fatal: profiling is optional
	}

	p.perfFDs = append(p.perfFDs, fd)

	p.logger.Info("CPU profiler started",
		zap.Int("sample_rate", p.cfg.SampleRate),
	)

	return nil
}

func (p *linuxProfiler) Stop() error {
	close(p.stopCh)
	p.wg.Wait()

	for _, fd := range p.perfFDs {
		unix.Close(fd)
	}

	return nil
}

func unsafe_Sizeof_PerfEventAttr() uintptr {
	return 120 // sizeof(struct perf_event_attr) on modern kernels
}
