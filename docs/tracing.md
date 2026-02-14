<!-- Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved. -->
<!-- Author: Madhukar Beema, Distinguished Engineer -->

# Distributed Tracing

## Overview

Olly provides zero-instrumentation distributed tracing via eBPF. By intercepting network syscalls at the kernel level, Olly captures request/response pairs and automatically injects [W3C Trace Context](https://www.w3.org/TR/trace-context/) (`traceparent`) headers into outbound HTTP requests. No application code changes are required.

Key properties:

- **Kernel-level injection** --- `sk_msg` injects `traceparent` headers directly into TCP send buffers
- **Synchronous context generation** --- BPF generates trace context at `read()` time, before `sendmsg()` fires
- **Graceful degradation** --- falls back to heuristic trace stitching when BPF injection is unavailable
- **Zero traffic impact** --- `sk_msg` always returns `SK_PASS`; injection failures are silent

## Architecture

```
                        Upstream Service
                              |
                     HTTP request (may contain traceparent)
                              |
                              v
   +----------------------------------------------------------+
   |                  Linux Kernel (eBPF)                      |
   |                                                           |
   |  kretprobe/sys_read ──> maybe_generate_trace_ctx()        |
   |     |  Detects HTTP, extracts/generates traceID+spanID    |
   |     |  Writes to thread_trace_ctx map                     |
   |     v                                                     |
   |  ringbuf event ──> Userspace Agent                        |
   |                                                           |
   |  sockops (ACTIVE_ESTABLISHED) ──> sock_ops_map (sockhash) |
   |                                                           |
   |  sk_msg ──> Reads thread_trace_ctx                        |
   |     |  Injects "traceparent: 00-{traceID}-{spanID}-01\r\n"|
   |     |  into outbound HTTP request headers                 |
   |     v                                                     |
   +----------------------------------------------------------+
                              |
                     HTTP request (with traceparent)
                              |
                              v
                       Downstream Service
```

### Component Roles

| Component | BPF Program Type | Purpose |
|-----------|-----------------|---------|
| `kretprobe/sys_read` | kretprobe | Detects inbound HTTP requests, generates trace context synchronously |
| `olly_sockops` | sockops (cgroup) | Populates sockhash on outbound TCP `ACTIVE_ESTABLISHED` |
| `olly_sk_msg` | sk_msg | Reads `thread_trace_ctx`, injects `traceparent` header into outbound HTTP |
| Agent (userspace) | --- | Enriches request pairs, creates OTEL spans, manages thread context lifecycle |

### Dual-Path Strategy

1. **Primary: BPF sk_msg injection** --- kernel-level header injection provides accurate, low-overhead cross-service tracing
2. **Fallback: Trace stitching** --- when sk_msg is unavailable (HTTPS between services, cgroup v2 missing, kernel too old), the agent matches CLIENT and SERVER spans by address, timestamp, HTTP method, and path

## How Traceparent Propagation Works

### Inbound Request Processing

When an HTTP request arrives, `kretprobe/sys_read` calls `maybe_generate_trace_ctx()`:

1. **Check connection direction** --- only inbound connections (`DIR_INBOUND` via `conn_map`) trigger context generation
2. **Detect HTTP** --- scan first bytes for method (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`)
3. **Scan for existing traceparent** --- `find_traceparent()` searches payload for `traceparent: 00-`
4. **Generate context**:
   - **Upstream traceparent present**: extract the 32-hex trace ID, generate a new 16-hex span ID
   - **No upstream traceparent**: generate both trace ID (128-bit random) and span ID (64-bit random) via `bpf_get_prandom_u32()`
5. **Store** --- write formatted header to `thread_trace_ctx` map keyed by `{pid, tid}`

### Three-Priority System (Userspace)

The agent's `OnDataIn` callback resolves trace context with this priority:

| Priority | Source | When Used |
|----------|--------|-----------|
| 1 | **HTTP header extraction** | Incoming request contains `traceparent:` header |
| 2 | **BPF-generated context** | `GetTraceContext()` reads from `thread_trace_ctx` map |
| 3 | **Agent-generated** | No context from either source; agent generates new IDs |

After resolution, the agent calls `SetTraceContext()` to populate the BPF map for `sk_msg` injection of outbound requests on the same thread.

### Why BPF-Side Generation?

There is a race condition between userspace processing and outbound requests:

- `sk_msg` fires synchronously at `sendmsg()` time
- The Go agent processes events asynchronously (seconds of delay)
- If the application sends an outbound request before the agent processes the inbound one, `sk_msg` would find an empty map entry

Generating context in `kretprobe/sys_read` (which fires synchronously when the application reads the inbound request) ensures the `thread_trace_ctx` map is populated **before** any outbound `sendmsg()` can fire.

## Span Hierarchy Mechanics

### Thread Trace Context Structure

```go
type threadTraceCtx struct {
    TraceID      string    // shared across all spans in the trace
    SpanID       string    // injected via sk_msg -> becomes CLIENT span's own spanID
    ServerSpanID string    // SERVER span's own spanID; CLIENT spans use as parentSpanID
    ParentSpanID string    // from incoming traceparent (cross-service parent link)
    Created      time.Time // for 30-second expiry
}
```

### Span Chain

For a request flowing through Service A -> Service B -> Service C:

```
Service A (SERVER)         Service B (SERVER)         Service C (SERVER)
  spanID: S1                 spanID: S3                 spanID: S5
  parentSpanID: (upstream)   parentSpanID: C2           parentSpanID: C4
       |                          |                          |
       v                          v                          v
Service A (CLIENT)         Service B (CLIENT)
  spanID: C2                 spanID: C4
  parentSpanID: S1           parentSpanID: S3
  --- sk_msg injects ---     --- sk_msg injects ---
  traceparent: ...C2...      traceparent: ...C4...
```

The chain works as:
```
SERVER(S1) --> CLIENT(C2, parent=S1) --> SERVER(S3, parent=C2) --> CLIENT(C4, parent=S3) --> SERVER(S5, parent=C4)
```

### How `enrichPairContext()` Builds the Chain

For each completed request pair, the agent looks up the thread's `threadTraceCtx`:

- **All pairs**: inherit `ParentTraceID = tctx.TraceID` and `ParentSpanID = tctx.ServerSpanID`
- **Outbound (CLIENT)**: additionally set `InjectedSpanID = tctx.SpanID` (the span ID that `sk_msg` injected into the outbound request)
- **Inbound (SERVER)**: clear thread context and BPF map entry (request is complete)
- **Expiry**: contexts older than 30 seconds are discarded

### How `ProcessPair()` Assigns Span IDs

| Span Kind | `span.TraceID` | `span.SpanID` | `span.ParentSpanID` |
|-----------|----------------|---------------|---------------------|
| SERVER (with HTTP traceparent) | from header | new random | header's spanID |
| SERVER (with thread context) | `ParentTraceID` | `ParentSpanID` (= ServerSpanID) | from upstream traceparent |
| CLIENT | `ParentTraceID` | `InjectedSpanID` (or new random) | `ParentSpanID` (= ServerSpanID) |
| Fallback (no context) | new random | new random | empty |

## Data Flow (End-to-End)

Step-by-step for a request traversing two services:

1. **Inbound request arrives at Service A**
   - `kretprobe/sys_read` fires, `maybe_generate_trace_ctx()` generates traceID `T1` + spanID `C2`, stores in `thread_trace_ctx[pid,tid]`
   - Ring buffer event sent to agent

2. **Agent processes inbound data** (`OnDataIn`)
   - Reads BPF context via `GetTraceContext()` -> gets `T1`, `C2`
   - Generates `ServerSpanID` `S1`
   - Calls `SetTraceContext(pid, tid, T1, C2)` to refresh BPF map

3. **Service A sends outbound request to Service B**
   - `sk_msg` intercepts `sendmsg()`, reads `thread_trace_ctx[pid,tid]`
   - Scans for HTTP method, finds `\r\n\r\n` header boundary
   - Inserts `traceparent: 00-T1-C2-01\r\n` (70 bytes) via `bpf_msg_push_data()`
   - Returns `SK_PASS`

4. **Agent processes request pair** (`enrichPairContext`)
   - Outbound pair gets `ParentTraceID=T1`, `ParentSpanID=S1`, `InjectedSpanID=C2`

5. **`ProcessPair()` creates CLIENT span**
   - `TraceID=T1`, `SpanID=C2`, `ParentSpanID=S1`

6. **Service B receives request with `traceparent: 00-T1-C2-01`**
   - `kretprobe/sys_read` fires, `find_traceparent()` extracts `T1`
   - Generates new spanID `C4`, stores `thread_trace_ctx` with traceID `T1`

7. **Agent on Service B processes inbound**
   - HTTP extraction finds `traceparent`, gets `TraceID=T1`, `ParentSpanID=C2`
   - Generates `ServerSpanID=S3`

8. **`ProcessPair()` creates SERVER span for Service B**
   - `TraceID=T1`, `SpanID=S3`, `ParentSpanID=C2`

Result: a fully connected trace `S1 -> C2 -> S3 -> C4 -> ...` sharing trace ID `T1`.

## What's Working (Verified)

Verified on EC2 (Amazon Linux 2023, kernel 6.1):

- Cross-service trace ID propagation via sk_msg injection (11/11 traces correct)
- Proper chained span hierarchy: SERVER -> CLIENT -> downstream SERVER (0 flat traces, 0 broken chains)
- IPv4 and IPv6 support (Go defaults to `::` / IPv6; BPF handles `AF_INET6`)
- BPF-side traceparent extraction from upstream headers (`find_traceparent()`)
- sk_msg header injection for HTTP/1.1 requests
- Fallback trace stitching when injection is unavailable
- SSL/TLS plaintext capture via uprobes on `SSL_read`/`SSL_write`
- macOS stub provider (logs + metrics functional; tracing requires Linux)
- On-demand hook activation (zero overhead when dormant)

## Key Components Reference

### Source Files

| File | Role | Key Functions |
|------|------|---------------|
| `pkg/hook/ebpf/bpf/olly.bpf.c` | BPF programs | `maybe_generate_trace_ctx()`, `find_traceparent()`, `olly_sockops`, `olly_sk_msg` |
| `pkg/hook/provider.go` | TraceInjector interface | `SetTraceContext()`, `ClearTraceContext()`, `GetTraceContext()`, `SupportsInjection()` |
| `pkg/hook/ebpf/loader.go` | BPF map operations | `setTraceContext()`, `clearTraceContext()`, `getTraceContext()`, `attachSockopsAndSkMsg()` |
| `pkg/hook/ebpf/provider_linux.go` | Injection setup | `setupTraceInjection()` --- cgroup v2 discovery, sockops+sk_msg attach |
| `pkg/agent/agent.go` | Trace context orchestration | `OnDataIn` (priority resolution), `enrichPairContext()` (span hierarchy) |
| `pkg/traces/processor.go` | Span creation | `ProcessPair()` --- RequestPair to OTEL Span |
| `pkg/traces/stitcher.go` | Fallback matching | `matchServerSpan()` --- CLIENT/SERVER pairing by addr+time+method+path |
| `pkg/protocol/http.go` | Header parsing | `ExtractTraceContext()` --- traceparent + tracestate extraction |
| `pkg/reassembly/request.go` | Request pair model | `RequestPair` struct with `ParentTraceID`, `ParentSpanID`, `InjectedSpanID`, `Direction` |

### BPF Maps

| Map | Type | Key | Value | Max Entries | Purpose |
|-----|------|-----|-------|-------------|---------|
| `thread_trace_ctx` | HASH | `{pid, tid}` | `trace_ctx` (valid flag + 70-byte header) | 8,192 | Thread -> traceparent for sk_msg |
| `sock_ops_map` | SOCKHASH | `sock_key` (4-tuple, `__u32[4]` IPs) | socket | 16,384 | Outbound socket lookup for sk_msg |
| `conn_map` | HASH | `{pid, fd}` | `{addr, port, direction}` | 16,384 | Connection metadata + direction |
| `tracing_enabled` | ARRAY | `0` | `0` or `1` | 1 | On-demand tracing toggle |

### Configuration

```yaml
hook:
  enabled: true           # Enable eBPF hook provider
  on_demand: false        # Start active (true = start dormant)

tracing:
  enabled: true           # Enable span generation
  protocols:
    http:
      enabled: true
    grpc:
      enabled: true
    postgres:
      enabled: true
    mysql:
      enabled: true
    redis:
      enabled: true
    mongodb:
      enabled: true
    dns:
      enabled: true

correlation:
  enabled: true           # Enable log-trace correlation
  strategy: pid_tid_timestamp
  window: 100ms           # Correlation time window
```

## Log-Trace Correlation

The correlation engine (`pkg/correlation/engine.go`) links log records to active trace spans using PID+TID+timestamp matching. When a log is emitted during an active span on the same thread, the log is enriched with `traceID`, `spanID`, and `serviceName`.

### How It Works

Correlation requires two things: (1) capturing application logs with PID+TID context, and (2) having trace context registered before the log is emitted.

#### Log Capture via eBPF

Application logs are captured through the `write()` kprobe. The eBPF program maintains a `log_fd_map` --- an allowlist of file descriptors that should emit `EVENT_LOG_WRITE` events. When a `write()` syscall targets a registered FD, the kprobe emits the log payload with the kernel-provided PID and TID.

FD registration happens automatically when a process first connects or accepts a connection:

```
eventConnect/eventAccept ──> registerLogFDs(pid)
                                ├─ Register fd 1 (stdout) and fd 2 (stderr)
                                └─ Scan /proc/<pid>/fd via readlink
                                     ├─ *.log files  → register
                                     └─ /var/log/*    → register
```

This catches all common log destinations: stdout/stderr (containers), application log files (`app.log`, `flask.log`), and system log paths (`/var/log/`). Each PID is scanned once and the results are cached.

#### Early Span Registration

Trace context is registered with the correlation engine at **request arrival time** (in the `OnDataIn` callback), not at span completion. This ensures the correlation engine has an active span BEFORE any log writes happen during request processing.

```
HTTP request arrives
    │
    ├─ OnDataIn ──> connCtx created (traceID, serverSpanID)
    │                 └─ correlation.RegisterSpanStart(PID, TID, traceID, spanID)
    │                      └─ activeSpans[PID<<32|TID] = SpanContext
    │
    ├─ App processes request
    │     └─ write() syscall ──> EVENT_LOG_WRITE ──> processLog()
    │                              └─ correlation.EnrichLog(record)
    │                                   └─ Match! → traceID + spanID attached
    │
    └─ Response sent ──> span completes ──> processSpan()
                           └─ correlation.RegisterSpanStart(PID, TID, ..., span.StartTime)
                                └─ updates with final span details + operation name
```

Without early registration, logs would always be exported before trace context was available (spans complete after the response is sent, but logs are written during request processing).

### Matching Strategies (in priority order)

1. **Exact PID+TID** --- best accuracy; both process and thread match an active span within the time window
2. **PID-only** --- fallback when TID is unavailable (TID=0) or different (Go goroutine migration); matches any span on the same process
3. **Retroactive** --- logs arriving before their span are buffered (up to 1000) and correlated when `RegisterSpanStart()` fires

### PID/TID Sources

| Log Source | PID | TID | Accuracy |
|------------|-----|-----|----------|
| Hook-captured (`write()` kprobe) | From kernel | From kernel | Exact |
| JSON logs (`"pid":N, "tid":N`) | Parsed from field | Parsed from field | Exact |
| Syslog (`process[pid]: ...`) | From header | Extracted from body | PID exact, TID best-effort |
| Plain text (`pid=N tid=N`) | Regex extraction | Regex extraction | Best-effort |
| Plain text (no PID/TID) | 0 | 0 | No correlation |

The parser recognizes common PID/TID patterns in log text: `pid=123`, `PID 123`, `process=123`, `tid=456`, `TID 456`, `thread=456`, `thread_id=456`.

### Enrichment Output

When a log is correlated, `SetTraceContext()` populates:
- `LogRecord.TraceID`, `.SpanID`, `.ServiceName` --- used by OTLP export (`traceId`/`spanId` proto fields)
- `Attributes["trace_id"]`, `["span_id"]` --- log record attributes surfaced as detected fields in Grafana Loki
- `Attributes["service.name"]` --- links logs to the originating service
- `Attributes["traceparent"]` --- W3C format `00-{traceID}-{spanID}-01` for downstream systems without OTLP support

The dual export (OTLP proto fields + attributes) ensures trace context is visible across different backends. Grafana Loki stores OTLP `traceId` as structured metadata, but surfaces `trace_id` attributes as detected fields --- enabling "View trace" navigation from Loki to Tempo.

### Time Window

The correlation window (default: 100ms, configurable via `correlation.window`) defines how far a log's timestamp can be from a span's start/end time and still be considered part of that span. The `startTime` parameter passed to `RegisterSpanStart` uses the actual request arrival time (from eBPF event timestamp), not the registration call time, ensuring the window is accurate even for slow requests.

## Challenges & Known Limitations

### Protocol Support
- **HTTP/1.1 only** --- sk_msg scans for ASCII HTTP methods and `\r\n\r\n` header boundaries. HTTP/2 uses binary framing (HPACK-compressed headers) which cannot be injected this way.
- **gRPC** --- uses HTTP/2; same binary framing limitation applies to header injection (gRPC spans are captured but not propagated cross-service via injection).

### Header Scanning
- **248-byte scan limit** (`SCAN_MAX`) --- sk_msg scans the first 248 bytes of the TCP payload for the `\r\n\r\n` header boundary. Requests with very large headers (many cookies, auth tokens) may have the boundary beyond this limit, causing injection to be skipped.
- **MAX_CAPTURE=256 bytes** --- payload captured per event is truncated; does not affect injection but limits what the agent sees for protocol parsing.

### Thread Context Lifetime
- **30-second TTL** --- thread trace context expires after 30 seconds. Long-running requests (large file uploads, streaming) may lose their trace context before the response completes.
- **Per-thread only** --- context is keyed by `{PID, TID}`. Go goroutines that migrate between OS threads (the default) may not inherit trace context from the original request handler thread.
- **Cleanup interval** --- stale contexts are swept every 30 seconds in the agent's background loop.

### Kernel Requirements
- **Cgroup v2 required** --- sockops and sk_msg attach to cgroup v2. Systems using cgroup v1 exclusively will fall back to trace stitching.
- **Kernel 6.1+** --- uses legacy `BPF_PROG_ATTACH` for sk_msg (not `BPF_LINK_CREATE` which requires 6.7+).
- **Linux only** --- macOS and Windows use a stub provider; tracing requires Linux with BPF support.

### Trace Stitching Limitations
- **Heuristic matching** --- the stitcher matches CLIENT and SERVER spans by remote address/port, timestamp proximity, HTTP method, and URL path. High-concurrency scenarios with identical endpoints may produce incorrect matches.
- **Default window: 1 second** --- CLIENT and SERVER spans must occur within this window to be matched. The stitcher does not cross service boundaries without network address correlation.
- **No stitching for non-HTTP** --- only HTTP method and path are used for disambiguation; database protocol spans rely solely on address+time matching.

### Injection Edge Cases
- **sk_msg always returns SK_PASS** --- if injection fails (no context, no header boundary found, push_data fails), the original request is sent unmodified. This is safe but means some requests silently miss injection.
- **IPv4-mapped IPv6** --- handled correctly in sockops key construction, but unusual network configurations with mixed addressing may cause sockhash lookup misses.

## Future Improvements

### Protocol Coverage
- **HTTP/2 traceparent injection** --- requires understanding HPACK encoding to inject a `traceparent` pseudo-header or use the `grpc-trace-bin` header for gRPC
- **W3C Baggage propagation** --- inject `baggage:` header alongside `traceparent` for arbitrary context propagation

### Trace Context
- **Sampling support** --- honor and propagate the flags byte (`01` = sampled) to implement head-based sampling decisions
- **Multi-goroutine propagation** --- track goroutine creation (`runtime.newproc`) to propagate trace context across goroutine boundaries, not just OS threads
- **Configurable TTL** --- make the 30-second thread context expiry configurable for workloads with long-lived requests
- **Configurable SCAN_MAX** --- allow tuning the sk_msg header scan limit for applications with large headers

### Platform & Architecture
- **ARM64 support** --- add `bpf2go` target for `arm64` (currently `amd64` only)
- **Kernel version detection** --- use `BPF_LINK_CREATE` on kernel 6.7+ for better lifecycle management, fall back to `BPF_PROG_ATTACH` on older kernels

### Observability
- **Injection success/failure metrics** --- expose counters for sk_msg injection attempts, successes, and failure reasons (no context, no boundary, push_data error)
- **Stitcher match metrics** --- track how many spans are stitched vs. injected vs. orphaned
- **Integration tests** --- automated E2E tests for cross-service trace propagation with assertion on span hierarchy

### Stitcher Improvements
- **Weighted scoring** --- combine time proximity, method, path, and content-length into a confidence score for better matching accuracy under high concurrency
- **Non-HTTP disambiguation** --- use database query fingerprints or Redis command types to improve stitcher accuracy for database protocol spans
