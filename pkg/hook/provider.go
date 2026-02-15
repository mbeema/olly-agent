// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package hook

import "context"

// Callbacks for hook events.
type Callbacks struct {
	OnConnect func(pid, tid uint32, fd int32, remoteAddr uint32, remotePort uint16, ts uint64)
	OnAccept  func(pid, tid uint32, fd int32, remoteAddr uint32, remotePort uint16, ts uint64)
	OnDataOut func(pid, tid uint32, fd int32, data []byte, ts uint64)
	OnDataIn  func(pid, tid uint32, fd int32, data []byte, ts uint64)
	OnClose    func(pid, tid uint32, fd int32, ts uint64)
	OnLogWrite func(pid, tid uint32, fd int32, data []byte, ts uint64)
}

// HookProvider is the interface for hook event sources.
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

	// Name returns the provider name (e.g., "ebpf", "stub").
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

// EphemeralPortProvider is implemented by providers that can look up the
// local ephemeral port of outbound connections from BPF sockops data.
// This enables deterministic same-host CLIENT↔SERVER trace linking by
// matching CLIENT.LocalPort == SERVER.RemotePort.
//
// Use type assertion to check if a HookProvider supports this:
//
//	if epp, ok := provider.(EphemeralPortProvider); ok {
//	    localPort, cookie, ok := epp.GetEphemeralPort(pid, remoteAddr, remotePort)
//	}
type EphemeralPortProvider interface {
	// GetEphemeralPort returns the local port and socket cookie for an
	// outbound connection identified by (pid, remoteAddr, remotePort).
	GetEphemeralPort(pid uint32, remoteAddr uint32, remotePort uint16) (localPort uint16, cookie uint64, ok bool)
}

// EventTraceProvider is implemented by providers that embed BPF-generated
// trace context directly in ring buffer events, eliminating the race condition
// between BPF map writes and Go's asynchronous ring buffer processing.
//
// Use type assertion to check if a HookProvider supports this:
//
//	if etp, ok := provider.(EventTraceProvider); ok {
//	    traceID, spanID, ok := etp.GetEventTraceContext(pid, tid)
//	}
type EventTraceProvider interface {
	// GetEventTraceContext returns BPF-generated trace context from the most
	// recent ring buffer event for the given PID+TID. The context is consumed
	// on read (each event's context is used exactly once).
	// This is race-free because dispatch() sets context synchronously before
	// calling OnDataIn, and both run in the same goroutine.
	GetEventTraceContext(pid, tid uint32) (traceID, spanID string, ok bool)
}
