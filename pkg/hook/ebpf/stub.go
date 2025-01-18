package ebpf

import (
	"context"
	"fmt"

	"github.com/mbeema/olly/pkg/hook"
	"go.uber.org/zap"
)

// StubProvider is a no-op HookProvider for platforms where eBPF is not available
// (macOS, Windows, or Linux kernels < 5.8). The agent starts normally — logs,
// metrics, and profiling work. Only hook-based tracing is unavailable.
type StubProvider struct {
	reason string
	logger *zap.Logger
}

var _ hook.HookProvider = (*StubProvider)(nil)

// NewStubProvider creates a stub provider that logs why eBPF is unavailable.
func NewStubProvider(reason string, logger *zap.Logger) *StubProvider {
	return &StubProvider{reason: reason, logger: logger}
}

func (s *StubProvider) Start(_ context.Context, _ hook.Callbacks) error {
	s.logger.Warn("hook tracing unavailable — running in stub mode",
		zap.String("reason", s.reason),
	)
	return nil
}

func (s *StubProvider) Stop() error {
	return nil
}

func (s *StubProvider) EnableTracing() error {
	return fmt.Errorf("tracing unavailable: %s", s.reason)
}

func (s *StubProvider) DisableTracing() error {
	return nil
}

func (s *StubProvider) IsTracingEnabled() bool {
	return false
}

func (s *StubProvider) Name() string {
	return "stub"
}
