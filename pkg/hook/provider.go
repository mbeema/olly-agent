package hook

import "context"

// HookProvider is the interface for hook event sources.
// Implementations include the eBPF provider (Linux 5.8+) and the legacy
// Unix DGRAM socket manager (LD_PRELOAD-based).
type HookProvider interface {
	// Start begins capturing hook events and dispatching to callbacks.
	Start(ctx context.Context, callbacks Callbacks) error

	// Stop shuts down the hook provider and releases resources.
	Stop() error

	// EnableTracing activates tracing in observed processes.
	EnableTracing() error

	// DisableTracing deactivates tracing. Hooks become pass-through.
	DisableTracing() error

	// IsTracingEnabled returns the current tracing state.
	IsTracingEnabled() bool

	// Name returns the provider name (e.g., "ebpf", "socket", "stub").
	Name() string
}
