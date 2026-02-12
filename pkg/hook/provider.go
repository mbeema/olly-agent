// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

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

// TraceInjector is an optional interface that HookProvider implementations
// can support for injecting W3C traceparent headers into outbound HTTP
// requests at the kernel/socket level. This enables cross-service distributed
// tracing without any application instrumentation.
//
// Use type assertion to check if a HookProvider supports injection:
//
//	if injector, ok := provider.(TraceInjector); ok {
//	    injector.SetTraceContext(pid, tid, traceID, spanID)
//	}
type TraceInjector interface {
	// SetTraceContext stores trace context for a thread. When the thread
	// makes an outbound HTTP request, the traceparent header will be
	// injected automatically by the BPF sk_msg program.
	SetTraceContext(pid, tid uint32, traceID, spanID string) error

	// ClearTraceContext removes trace context for a thread after the
	// inbound request has been fully processed.
	ClearTraceContext(pid, tid uint32) error

	// GetTraceContext reads the BPF-generated trace context for a thread.
	// Returns traceID, spanID, ok. If BPF generated a trace context in
	// the kretprobe (before userspace processing), the agent should use
	// that trace ID to stay consistent with sk_msg injection.
	GetTraceContext(pid, tid uint32) (traceID, spanID string, ok bool)

	// SupportsInjection returns true if the provider has successfully
	// set up the sockops + sk_msg programs for traceparent injection.
	SupportsInjection() bool
}
