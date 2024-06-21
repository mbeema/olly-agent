# Olly v2 - OTEL Standard Auto-Instrumentation Requirements

## Executive Summary

This document defines the comprehensive requirements for making Olly v2 a fully OTEL-compliant auto-instrumentation agent at the OS level. Requirements are derived from:
- W3C Trace Context specification (Level 1 + Level 2)
- OpenTelemetry Semantic Conventions v1.39+
- OTEL Log Data Model
- Gap analysis of current Olly v2 codebase
- Competitive analysis (OBI/Beyla, Odigos, Datadog, Dynatrace, Pixie)

---

## R1. W3C Trace Context Propagation (CRITICAL)

### R1.1 Auto-Inject `traceparent` on Outbound Requests

**Current state:** Olly passively reads `traceparent` from requests but never injects it. The `TraceParent()` method on `Span` is dead code.

**Requirement:** When Olly observes an outbound HTTP/gRPC request that does NOT contain a `traceparent` header, the hook library (libolly.c) MUST inject one before the data leaves the process.

**Implementation approach:**
- In `SSL_write` / `send` / `write` hooks in libolly.c, detect HTTP request headers
- If no `traceparent` header is present, inject one: `traceparent: 00-{traceID}-{spanID}-01`
- The traceID/spanID can be generated in the C hook library (using /dev/urandom or getrandom()) or provided by the Go agent via the Unix socket back-channel
- For responses flowing back to the caller, if the caller provided a `traceparent`, the response should maintain the same traceID

**W3C spec compliance:**
- Format: `traceparent: {version}-{trace-id}-{parent-id}-{trace-flags}`
- Version: `00`
- trace-id: 32 hex lowercase chars (16 bytes), MUST NOT be all zeros
- parent-id: 16 hex lowercase chars (8 bytes), MUST NOT be all zeros
- trace-flags: `01` (sampled)

**Reference:** W3C Trace Context Level 1 - https://www.w3.org/TR/trace-context/

### R1.2 Support `tracestate` Header

**Current state:** Zero handling of `tracestate` anywhere in the codebase.

**Requirement:** When `tracestate` is present on an incoming request, it MUST be propagated to all outgoing requests made within the same trace context. The agent MUST NOT drop or modify vendor entries it does not understand.

**Rules:**
- Maximum 32 list-members
- Each entry: `key=value` format, comma-separated
- Olly MAY add its own entry with vendor key (e.g., `olly=...`)
- If `tracestate` exceeds 512 bytes, truncate from the right (oldest entries)
- Propagate as-is to downstream calls

**Level 2 additions:**
- Support `random` flag (FLAG_RANDOM = 0x02) in trace-flags: indicates traceID was generated with randomness, important for consistent probability sampling
- If Olly generates a traceID, it MUST use cryptographic randomness and set the random flag

### R1.3 Context Propagation via Hook Library

**Current state:** libolly.c only captures data passively; it never modifies outbound data.

**Requirement:** Add a back-channel from the Go agent to libolly.c that enables header injection:

**Option A: Shared memory approach**
- Agent writes trace context to a shared memory region keyed by (PID, TID)
- Hook library reads from shared memory before outbound send
- Low latency but complex synchronization

**Option B: Buffer modification in hook**
- Hook library detects HTTP request in the send buffer
- If no `traceparent` found, generates one and splices it into the buffer
- Requires careful buffer management (expand buffer if needed)
- Similar to how Beyla uses `bpf_probe_write_user` but at userspace level

**Option C: (Recommended) Request-rewrite in hook**
- Hook intercepts `SSL_write`/`send` calls
- Scans for HTTP request pattern (method + path + HTTP/1.1)
- If `traceparent` header absent, inject before end of headers (`\r\n\r\n`)
- Use thread-local storage for current trace context (agent pushes via socket)
- Advantage: Works because we're already in userspace with LD_PRELOAD

### R1.4 Cross-Service Trace Linking

**Requirement:** When multiple services are instrumented with Olly:
- Outbound request from Service A gets `traceparent` injected by Olly
- Inbound request to Service B is received with `traceparent`
- Service B's spans use the same traceID, creating a linked distributed trace
- Service B's outbound calls propagate the same traceID with a new spanID

### R1.5 Fix `TraceParent()` Sampled Flag

**Current state:** `span.go` sets trace-flags to `00` when `Status == StatusError` and `01` otherwise. This conflates error status with sampling.

**Requirement:** The sampled flag (`01`) indicates the trace is being recorded. Since Olly records all traces, the flag should ALWAYS be `01` regardless of span status. Error status is conveyed through span status, not trace-flags.

---

## R2. Span Semantic Convention Compliance (HIGH)

### R2.1 Migrate to Stable HTTP Conventions

**Current state:** Uses deprecated attribute names throughout.

| Current (Deprecated) | Required (Stable v1.23+) |
|----------------------|--------------------------|
| `http.method` | `http.request.method` |
| `http.target` | `url.path` + `url.query` |
| `http.status_code` | `http.response.status_code` |
| `http.host` | `server.address` + `server.port` |
| `http.user_agent` | `user_agent.original` |
| `net.peer.ip` | `network.peer.address` |
| `net.peer.port` | `network.peer.port` |
| `net.transport` | `network.transport` |

**Additional attributes to add:**
- `url.scheme` - "http" or "https" (available via `pair.IsSSL`)
- `network.protocol.version` - "1.0", "1.1", "2", "3"
- `error.type` - HTTP status code class or exception type on error spans
- `http.request.body.size` / `http.response.body.size` - from Content-Length

### R2.2 Migrate to Stable Database Conventions

| Current (Deprecated) | Required (Stable) |
|----------------------|-------------------|
| `db.name` | `db.namespace` |
| `db.statement` | `db.query.text` |
| `db.operation` | `db.operation.name` |
| `db.mongodb.collection` | `db.collection.name` |

**Additional:**
- Add `db.query.summary` for low-cardinality span naming (e.g., "SELECT users")
- Add `server.address` and `server.port` on all DB client spans

### R2.3 Fix Span Kind Detection

**Current state:** Span kind is hardcoded to `CLIENT` in `processor.go`.

**Requirement:** Detect whether a connection is inbound or outbound:
- **SERVER**: The local process accepted the connection (was listening)
- **CLIENT**: The local process initiated the connection (called connect)

The `ConnTracker` already knows this from connect/accept events. Add:
- `ConnInfo.Direction` field: `INBOUND` vs `OUTBOUND`
- Inbound connections (accept) → SERVER spans
- Outbound connections (connect) → CLIENT spans

### R2.4 Exception Event Attributes

**Current state:** `SetError` only sets `exception.message`.

**Requirement:** Per OTEL exception semantic conventions:
- `exception.type` - Type/class of the error
- `exception.message` - Error description
- `exception.stacktrace` - Optional, where available

---

## R3. Log Data Model Compliance (HIGH)

### R3.1 Add `SeverityNumber`

**Current state:** Only `SeverityText` is set. `SeverityNumber` is never populated.

**Requirement:** Map log levels to OTEL severity numbers:

| LogLevel | SeverityText | SeverityNumber |
|----------|-------------|----------------|
| TRACE | TRACE | 1 |
| DEBUG | DEBUG | 5 |
| INFO | INFO | 9 |
| WARN | WARN | 13 |
| ERROR | ERROR | 17 |
| FATAL | FATAL | 21 |

### R3.2 Add `ObservedTimestamp`

**Current state:** Not set on OTLP log records.

**Requirement:** Set `ObservedTimestampUnixNano` to the time the log was received by the collector (time.Now() at collection), distinct from `TimestampUnixNano` (the event time parsed from the log line).

### R3.3 Add `TraceFlags`

**Current state:** Not set.

**Requirement:** When a log record is correlated with a trace, set `Flags` to `0x01` (sampled). When not correlated, leave as `0x00`.

### R3.4 Add Log Source Attributes

**Requirement:** Include standard log file attributes:
- `log.file.path` - Full path to the log file
- `log.file.name` - Just the filename
- `log.iostream` - "stdout" or "stderr" if applicable

### R3.5 Preserve Numeric Level Through Export Pipeline

**Current state:** `LogLevel` (int) is converted to string early in the pipeline, losing numeric value.

**Requirement:** Either:
- Pass `LogLevel` as-is to the exporter and map there, OR
- Add a `SeverityNumber` field to the export `LogRecord` struct

---

## R4. Resource Attributes (HIGH)

### R4.1 Required Resource Attributes

**Current state:** Only 3 resource attributes: `service.name`, `telemetry.sdk.name`, `telemetry.sdk.language`.

**Must add (REQUIRED/RECOMMENDED):**

| Attribute | Source |
|-----------|--------|
| `telemetry.sdk.version` | Hardcoded version string (e.g., "0.1.0") |
| `host.name` | `os.Hostname()` |
| `host.arch` | `runtime.GOARCH` |
| `os.type` | `runtime.GOOS` |
| `process.pid` | Agent's own PID via `os.Getpid()` |
| `process.executable.name` | `os.Executable()` → filepath.Base |
| `process.runtime.name` | `"go"` |
| `process.runtime.version` | `runtime.Version()` |

**Should add (when available):**

| Attribute | Source |
|-----------|--------|
| `service.version` | Config or auto-detect |
| `service.instance.id` | Hostname + PID or UUID |
| `os.version` | Via gopsutil |
| `host.id` | Machine ID from /etc/machine-id or equivalent |

### R4.2 Per-Service Resource Attribution

**Current state:** All spans from all PIDs share a single resource with the agent's `service.name`.

**Requirement:** When monitoring multiple processes, each process should get its own ResourceSpans/ResourceLogs with:
- `service.name` - From discovery (per process)
- `process.pid` - The monitored process PID (not agent PID)
- `process.executable.name` - The monitored process name
- Other process-specific attributes

---

## R5. Metrics Compliance (MEDIUM)

### R5.1 Fix HTTP Request Metric Names

**Current state:** Non-standard names: `http.server.request_count`, `http.server.error_count`, `http.server.duration`.

**Required (OTEL stable):**

| Current | Required | Type | Unit |
|---------|----------|------|------|
| `http.server.request_count` | REMOVE (derived from histogram) | - | - |
| `http.server.error_count` | REMOVE (attribute on histogram) | - | - |
| `http.server.duration` | `http.server.request.duration` | Histogram | seconds |
| (missing) | `http.server.active_requests` | UpDownCounter | requests |
| (missing) | `http.client.request.duration` | Histogram | seconds |

**Required histogram attributes:**
- `http.request.method`
- `http.response.status_code`
- `url.scheme`
- `server.address`
- `server.port`
- `error.type` (when applicable)

### R5.2 Fix Histogram Bucket Count

**Current state:** OTLP histogram export produces `len(BucketCounts) == len(ExplicitBounds)`, violating the spec requirement of `len(BucketCounts) == len(ExplicitBounds) + 1`.

**Requirement:** Add the +Inf overflow bucket. The last element of BucketCounts must represent the count of values greater than the largest explicit bound.

### R5.3 Add `StartTimeUnixNano`

**Current state:** Not set on metric data points.

**Requirement:** For cumulative counters and histograms, set `StartTimeUnixNano` to when the metric collection began.

### R5.4 Fix CPU Label Bug

**Current state:** `time.Now().Format("cpu")` interprets "cpu" as a time format pattern, producing garbage.

**Requirement:** Use `fmt.Sprintf("cpu%d", i)` for CPU labels.

### R5.5 Separate Network Error Directions

**Current state:** `Errin + Errout` are summed together.

**Requirement:** Report separately with `direction` attribute: `transmit` and `receive`.

---

## R6. Log-to-Trace Correlation Enhancement (HIGH) -- COMPLETE

> **Status: IMPLEMENTED** via write() hook in libolly.c (Phase 3).
> Verified on EC2: 97% hook-log correlation rate, 100% of hook log traceIds match Tempo traces.
> Grafana Cloud: 50 hook logs in Loki, all with trace_id/span_id, linked to spans in Tempo.

### R6.1 Bidirectional Correlation -- COMPLETE

**Implementation:**
- Added `MSG_LOG_WRITE = 8` to wire protocol (libolly.c + protocol.go)
- libolly.c `write()` hook detects stdout/stderr/regular files via fstat()-based FD cache (256 entries)
- Agent `processHookLog()` splits lines, parses format (auto-detect JSON/syslog/plain), overrides PID/TID from syscall context
- Correlation engine matches PID+TID to active span, injects trace_id + span_id
- OTLP exporter sets top-level `traceId`/`spanId` fields on LogRecord proto (required for Grafana)
- Hook logs tagged `source=hook` vs file-tailed `source=file`

### R6.2 Configurable Log-Trace Mapping -- COMPLETE

**Implementation:**
- Config: `hook.log_capture: *bool` (yaml: `log_capture`, defaults to true)
- `LogCaptureEnabled()` helper returns true when nil (zero-config)
- File-tailed logs continue to work alongside hook logs (dual collection, no conflict)

### R6.3 Retroactive Correlation

**Current state:** Pending log buffer holds 1000 entries for retroactive correlation.

**Requirements (future enhancement):**
- Make buffer size configurable (default 10,000)
- Add configurable max age (default: 5s, current: 200ms = 2*window)
- Support correlation when log arrives before span starts (race condition)

---

## R7. Context Propagation Strategy (CRITICAL)

### R7.1 HTTP/1.1 Header Injection

**Where:** libolly.c `send`/`write`/`SSL_write` hooks

**Algorithm:**
1. Check if buffer contains HTTP request (starts with method)
2. Search for existing `traceparent:` header
3. If not found, search for `\r\n\r\n` (end of headers)
4. Get current trace context from thread-local storage
5. If no current context, generate new traceID + spanID
6. Insert `traceparent: 00-{traceID}-{spanID}-01\r\n` before the final `\r\n\r\n`
7. Adjust Content-Length if present (header injection changes offset only, not body)

**Constraints:**
- MUST NOT inject if `traceparent` already present (respect application instrumentation)
- MUST handle partial writes / fragmented headers
- Re-entrancy guard already exists (C1 fix) - ensure injection code is also guarded

### R7.2 HTTP/2 / gRPC Header Injection

**Where:** libolly.c SSL hooks (HTTP/2 is always over TLS in practice)

**Challenge:** HTTP/2 headers are HPACK-compressed. Injection requires:
1. Detect HTTP/2 traffic (connection preface or SETTINGS frame)
2. For HEADERS frames, decode existing headers
3. If no `:traceparent` pseudo-header, add one
4. Re-encode with HPACK
5. Update frame length

**Alternative for HTTP/2:** Since HTTP/2 is complex, consider:
- Inject at the application TLS layer before HTTP/2 framing (if hooking before the HTTP/2 library)
- OR use the Go agent to correlate by TCP connection + stream ID (simpler but OBI-only style)

### R7.3 Database Protocol Context Propagation

For database protocols (PostgreSQL, MySQL), context propagation is done via:
- **SQL comments**: Inject `/* traceparent=00-{traceID}-{spanID}-01 */` at the start of SQL queries
- This is the approach used by sqlcommenter (Google) and supported by many backends
- Configurable: off by default (may break query caches)

### R7.4 Context Inheritance for Correlation

**Requirement:** When a process receives an inbound request with `traceparent`, ALL outbound requests from the same PID+TID during that span's lifetime should use the same traceID with a new spanID as parent-id.

**Implementation:**
- Agent maintains active trace context per (PID, TID)
- On inbound request with traceparent → register context
- On outbound request from same (PID, TID) → child span of that context
- On span end → deregister context
- Thread-local storage in libolly.c stores current context per thread

---

## R8. Protocol-Specific Requirements

### R8.1 gRPC Metadata Propagation

**Requirement:** For gRPC, propagate trace context via gRPC metadata (which maps to HTTP/2 headers):
- `grpc-trace-bin`: Binary encoding of trace context (used by some implementations)
- `traceparent`: W3C header (carried as HTTP/2 header)

### R8.2 W3C Baggage Header

**Priority:** Medium

**Requirement:** Support the W3C Baggage specification:
- Extract `baggage` header from incoming requests
- Propagate to outgoing requests
- Make available as span attributes (configurable)
- Format: `key1=value1,key2=value2`
- Spec: https://www.w3.org/TR/baggage/

---

## R9. Competitive Feature Parity

### R9.1 Features to Match OBI/Beyla

| Feature | OBI/Beyla Status | Olly v2 Status | Action |
|---------|-----------------|----------------|--------|
| HTTP/HTTPS traces | Yes | Yes | None |
| gRPC traces | Yes | Yes | None |
| SQL database traces | Yes | Yes | None |
| Redis traces | Yes | Yes | None |
| MongoDB traces | Yes | Yes | None |
| Kafka traces | Limited | No | Add |
| RED metrics | Yes | Partial | Fix naming |
| Distributed tracing | Limited (Go only) | No injection | R1 + R7 |
| Log collection | No | Yes | Advantage |
| CPU profiling | No | Yes (Linux) | Advantage |
| Service map | Basic | Yes | Advantage |
| HTTP/2 multiplexing | Partial | Not yet (C7) | Implement |

### R9.2 Features to Match Datadog/Dynatrace

| Feature | Priority | Notes |
|---------|----------|-------|
| Trace-log auto-correlation | HIGH | We have it; needs OTEL compliance |
| Profile-trace correlation | MEDIUM | Link profiler data to individual spans |
| Runtime metrics | LOW | GC, heap, threads per monitored process |
| Dynamic instrumentation | LOW | Future - modify running process tracing |
| Service dependency map | DONE | Already implemented |

---

## R10. Configuration Requirements

### R10.1 New Configuration Options

```yaml
# Trace context propagation
propagation:
  enabled: true                    # Master switch
  inject_traceparent: true         # Inject traceparent on outbound
  inject_tracestate: true          # Propagate tracestate
  inject_baggage: false            # Propagate W3C baggage
  sql_comment_injection: false     # Inject trace context in SQL comments
  respect_existing: true           # Never overwrite existing traceparent

# Sampling
sampling:
  strategy: always_on              # always_on, probability, rate_limit
  probability: 1.0                 # For probability strategy
  rate_limit: 100                  # Max traces/sec for rate_limit strategy

# Log correlation
correlation:
  enabled: true
  window: 100ms                    # Time window for PID+TID matching
  buffer_size: 10000               # Pending log buffer
  buffer_max_age: 5s               # Max age for pending logs
  parse_trace_from_logs: true      # Extract trace_id from structured logs
  trace_id_fields:                 # Field names to check for trace IDs
    - trace_id
    - traceId
    - traceid
    - dd.trace_id

# Semantic conventions
semconv:
  version: "1.39"                  # Target semconv version
  emit_deprecated: false           # Also emit old attribute names (migration)
```

---

## Implementation Priority

### Phase 1 (Critical - Weeks 1-2)
1. **R1.1** - Auto-inject traceparent (C hook + Go agent coordination)
2. **R1.5** - Fix sampled flag
3. **R2.3** - Fix span kind detection (SERVER vs CLIENT)
4. **R4.1** - Add required resource attributes
5. **R3.1** - Add SeverityNumber to logs

### Phase 2 (High - Weeks 3-4)
6. **R2.1** - Migrate to stable HTTP semantic conventions
7. **R2.2** - Migrate to stable DB semantic conventions
8. **R5.1** - Fix HTTP metric names
9. **R5.2** - Fix histogram bucket count
10. **R1.2** - Support tracestate propagation
11. **R7.1** - HTTP/1.1 header injection in hook library

### Phase 3 (Medium - Weeks 5-6)
12. **R6.1** - Enhanced log-trace correlation ✅ COMPLETE (write() hook capture)
13. **R6.2** - Configurable log-trace mapping ✅ COMPLETE (hook.log_capture config)
14. **R3.2** - Add ObservedTimestamp
15. **R4.2** - Per-service resource attribution
16. **R7.4** - Context inheritance for correlation
17. **R5.3-R5.5** - Metrics fixes (StartTime, CPU label, network errors)

### Phase 4 (Enhancement - Weeks 7+)
18. **R7.2** - HTTP/2 header injection
19. **R7.3** - SQL comment injection
20. **R8.1** - gRPC metadata propagation
21. **R8.2** - W3C Baggage support
22. **R10.1** - Configuration options
23. **R9.1** - Kafka protocol support

---

## Remaining Unfixed Issues

From FIXES.md, these 3 issues remain:
- **C7**: HTTP/2 stream multiplexing (needed for R7.2)
- **H8**: IPv6 full address support
- **F2**: Kubernetes metadata enrichment (resource attributes)

These should be addressed alongside the relevant requirements above.

---

## References

- W3C Trace Context Level 1: https://www.w3.org/TR/trace-context/
- W3C Trace Context Level 2: https://www.w3.org/TR/trace-context-2/
- W3C Baggage: https://www.w3.org/TR/baggage/
- OTEL Semantic Conventions: https://opentelemetry.io/docs/specs/semconv/
- OTEL HTTP Semantic Conventions (stable): https://opentelemetry.io/docs/specs/semconv/http/http-spans/
- OTEL Database Semantic Conventions: https://opentelemetry.io/docs/specs/semconv/db/database-spans/
- OTEL Log Data Model: https://opentelemetry.io/docs/specs/otel/logs/data-model/
- OTEL Resource Conventions: https://opentelemetry.io/docs/specs/semconv/resource/
- OTEL HTTP Metrics: https://opentelemetry.io/docs/specs/semconv/http/http-metrics/
- OBI (OpenTelemetry eBPF Instrumentation): https://opentelemetry.io/docs/zero-code/obi/
- Grafana Beyla: https://grafana.com/oss/beyla-ebpf/
- Odigos: https://github.com/odigos-io/odigos
