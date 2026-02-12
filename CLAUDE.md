# CLAUDE.md

## Project Overview

Olly v2 is a cross-platform zero-instrumentation observability agent written in Go that uses userspace library hooking (LD_PRELOAD/DYLD_INSERT_LIBRARIES) to collect logs, metrics, traces, and profiles from uninstrumented services. It captures network I/O before the TLS encryption layer. Works on Linux, macOS, and Windows.

## Build Commands

```bash
make all              # Build hook library + Go binary
make build            # Build Go binary only
make hook             # Compile C hook library (libolly.so)
make clean            # Remove build artifacts
make test             # Run tests with race detector
make test-coverage    # Run tests with coverage report
make lint             # Run golangci-lint
make run              # Build & run (requires root for hook injection)
```

### Cross-compile & Deploy

```bash
deploy/build.sh           # Cross-compile linux/amd64 + package tarball
cd deploy/terraform && terraform apply  # Provision EC2
deploy/deploy.sh           # SCP + install on EC2
deploy/generate_traffic.sh # Generate demo traffic
deploy/verify.sh           # Check OTEL output files
deploy/analyze_traces.py   # Analyze trace linking quality (run on EC2)
```

## Architecture

Two hook providers, selected at startup (eBPF → socket → stub):

```
[eBPF mode — Linux kernel 5.8+]
Target Process ──syscalls──→ kprobes/kretprobes → ring buffer → Olly Agent
                 ──TCP──→ sockops/sk_msg (traceparent injection)

[Socket mode — fallback]
Target Process → libolly.so (LD_PRELOAD) → Unix DGRAM socket → Olly Agent

Olly Agent: HookProvider → ConnTracker → StreamReassembler
                                               ↓
                                       Protocol Parsers (HTTP/PG/MySQL/Redis/Mongo)
                                               ↓
            Log Collector → Correlation ← Span Generator → Stitcher
            Metrics Collector ──────────→ Export Manager → OTLP
            CPU Profiler ───────────────→
```

### Key Components (pkg/)

- **hook/ebpf/** - eBPF provider (Linux-only, build-tag gated): kprobes for syscalls, sockops/sk_msg for traceparent injection
- **hook/ebpf/bpf/olly.bpf.c** - BPF C code: kprobes (accept4/connect/read/write/close), sockops (sockhash), sk_msg (traceparent inject)
- **hook/ebpf/ringbuf.go** - Ring buffer reader, parses events including embedded trace context
- **hook/ebpf/provider_linux.go** - eBPF provider: loads BPF, manages maps, implements HookProvider + TraceInjector + EventTraceProvider
- **hook/provider.go** - HookProvider, TraceInjector, EventTraceProvider interfaces
- **hook/c/libolly.c** - LD_PRELOAD library (fallback): hooks connect/accept/accept4/send/recv/read/write/close + SSL_write/SSL_read
- **hook/manager.go** - Unix DGRAM socket listener for hook events (fallback provider)
- **conntrack/tracker.go** - fd → connection metadata mapping (direction-aware: inbound vs outbound)
- **reassembly/stream.go** - Per-connection byte buffer and message boundary detection
- **reassembly/request.go** - Request/response pair matching with direction propagation; TID always from request direction
- **protocol/*.go** - Protocol parsers (HTTP, PostgreSQL, MySQL, Redis, MongoDB)
- **traces/processor.go** - RequestPair → OTEL Span conversion with parent-child linking
- **traces/stitcher.go** - Bidirectional CLIENT↔SERVER matching for cross-service trace linking
- **correlation/engine.go** - PID+TID+timestamp log-trace linking
- **logs/collector.go** - Cross-platform file tailing via fsnotify
- **metrics/collector.go** - Host+process metrics via gopsutil
- **export/manager.go** - OTLP gRPC/HTTP + stdout exporters with batching
- **agent/agent.go** - Main orchestrator, wires all subsystems, thread context propagation
- **config/config.go** - YAML config loading, `LoadDir()` for multi-config, `Load()` for single-file
- **config/watcher.go** - fsnotify-based config directory watcher with 500ms debounce
- **discovery/discovery.go** - Service name auto-detection
- **servicemap/generator.go** - Service dependency graph from network flows

## Configuration

### Single-file mode
```bash
olly --config configs/olly.yaml
```

### Multi-config mode (auto-reload)
```bash
olly --config-dir deploy/configs/
```

Loads `base.yaml` + `traces.yaml` + `metrics.yaml` + `logs.yaml` + `profiles.yaml` from the directory. Changes are auto-detected via fsnotify and applied without restart. Signals can be enabled/disabled individually.

Key config sections: hook, tracing, logs, correlation, metrics, exporters, discovery, profiling, capture.

## Design Patterns

- **Subsystem lifecycle:** Each component implements Start/Stop with context
- **Event-driven:** Components communicate via callbacks (OnSpan, OnLog, OnMetric)
- **Thread safety:** sync.RWMutex for concurrent state access; atomic.Pointer for config
- **Batching:** All exporters batch and buffer (channel capacity: 10,000)
- **Inbound/outbound direction:** accept/accept4 → ConnInbound (SERVER spans), connect → ConnOutbound (CLIENT spans). Direction stored on streamState and propagated to RequestPair to survive connection close.
- **Thread context propagation:** PID+TID → trace context map in agent. Inbound HTTP request generates traceID, outbound CLIENT spans on same thread inherit it as parent.
- **TID from request direction:** Pair TID always comes from AppendSend (request read), never AppendRecv (response write) or close events. Go goroutines migrate between OS threads, so read() and write() on the same connection use different TIDs.
- **Cross-service trace linking (4 mechanisms):**
  1. sk_msg traceparent injection — BPF injects `traceparent:` header into outbound HTTP
  2. Thread context propagation — PID+TID map, inbound→outbound on same thread
  3. PID-only fallback — for Go goroutine TID mismatch (DB queries)
  4. Bidirectional stitcher — matches CLIENT↔SERVER by method/path/time; CLIENT adopts SERVER's traceID
- **Config auto-reload:** fsnotify watcher with 500ms debounce, `agent.Reload()` starts/stops subsystems based on config diff.

## libolly.c Hook Library Notes

- Uses raw Linux syscall fallbacks (`SYS_write`, `SYS_read`, etc.) for use before dlsym resolves function pointers
- All hooks have `if (!orig_*) return raw_*()` NULL guards to prevent segfault during init
- Constructor must NOT call `ensure_init()` — dlsym deadlocks on Amazon Linux 2023 glibc
- Uses atomic CAS + thread-local guard instead of pthread_once (re-entrancy safe)
- **CRITICAL:** Python uses `accept4()` not `accept()` on Linux — both must be hooked
- `dbg_write()` uses `raw_write()` on Linux to avoid re-entering write() hook
- Struct `msg_header_t` needs explicit `_reserved` padding field for 32-byte alignment
- `__attribute__((packed))` removes natural padding before uint64_t timestamp_ns
- traceparent injection only on `CONN_DIR_OUTBOUND` connections

## eBPF Hook Notes

- Requires Linux kernel 5.8+ (BPF ring buffer support)
- cilium/ebpf v0.20.0; bpf2go generates Go types from C
- Build tags: `provider_linux.go` / `provider_other.go` for platform split
- MAX_CAPTURE=256 bytes per ring buffer event — responses >256 bytes cause frameHTTP to fail boundary detection, triggering RemoveStream pair creation path
- sk_msg injects traceparent AFTER BPF captures data → captured payload doesn't contain the injected header
- BPF generates trace context in kretprobe_read (synchronous), Go agent processes asynchronously (~seconds delay)
- IPv6: Go's net.Listen defaults to `::` (AF_INET6). BPF must handle AF_INET6 or connections are invisible
- sock_key for IPv6: use `__u32[4]` for IP fields to hold both IPv4 and IPv6 in same sockhash
- sk_msg ALWAYS returns SK_PASS (never drops traffic)
- Stub provider on macOS: logs+metrics work, traces need Linux

## AWS Deploy Notes

- EC2: t3.small, Amazon Linux 2023, key=`~/.ssh/mbaws-20262.pem`
- PostgreSQL requires `pg_hba.conf` md5 auth rule inserted before ident rule for demo user
- Demo app needs `sudo pip3 install` (not `--user`), runs as root with LD_PRELOAD
- LD_PRELOAD must be set via wrapper script (env vars don't propagate through `sudo bash -c`)
- Olly agent must start BEFORE demo app (creates hook.sock for libolly.so)
- OTEL Collector uses file exporters to `/var/log/otel/{traces,metrics,logs}.json`
- libolly.so compiled on EC2 (C needs target glibc, can't cross-compile)
