//go:build !linux

package ebpf

import (
	"github.com/mbeema/olly/pkg/config"
	"github.com/mbeema/olly/pkg/hook"
	"go.uber.org/zap"
)

// NewProvider on non-Linux platforms returns a stub provider since eBPF
// is not available.
func NewProvider(cfg *config.Config, logger *zap.Logger) hook.HookProvider {
	return NewStubProvider("eBPF requires Linux", logger)
}
