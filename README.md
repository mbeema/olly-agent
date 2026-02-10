# Olly v2 - Zero-Instrumentation Observability Agent

Olly is a cross-platform observability agent that automatically collects **traces, logs, metrics, and profiles** from any process without code changes. It uses userspace library hooking (`LD_PRELOAD`) to intercept network I/O and system calls before TLS encryption.

## How It Works

```
Your App (unmodified)
    |
    v
libolly.so (LD_PRELOAD)         <-- hooks connect/accept/send/recv/write/close + SSL
    |
    v  Unix DGRAM socket
    |
Olly Agent
    ├── ConnTracker         ── tracks fd → connection metadata
    ├── StreamReassembler   ── reconstructs request/response pairs
    ├── Protocol Parsers    ── HTTP, PostgreSQL, MySQL, Redis, gRPC, DNS, MongoDB
    ├── Trace Processor     ── generates OTEL spans with parent-child linking
    ├── Log Collector       ── file tailing + write() hook capture (R6)
    ├── Correlation Engine  ── PID+TID → links logs to active traces
    ├── Metrics Collector   ── host, process, RED metrics
    └── OTLP Exporter       ── sends to any OTEL-compatible backend
            |
            v
    OTEL Collector → Grafana Cloud (Tempo + Loki + Mimir)
```

### Key Concepts (explain it like this)

**What does it do?** Olly sits between your app and the network. Every time your app makes a database query or HTTP request, Olly sees it, measures it, and creates a trace span. Every time your app writes a log line, Olly captures it with the PID and thread ID so it can link that log to the exact trace that caused it.

**How does it work without code changes?** It uses `LD_PRELOAD` — a Linux mechanism that lets you override system calls. When your app calls `write()`, `send()`, or `connect()`, Olly's C library intercepts the call, records telemetry, and then passes the call through to the real function. Your app never knows it's being observed.

**Why is log-trace correlation special?** Traditional log collectors read log files, but they lose the connection between "which request caused this log line." Olly captures logs at the `write()` syscall level, so it knows the PID and TID of the thread writing the log. The correlation engine matches this to the active trace span on that thread, injecting `trace_id` and `span_id` into each log record automatically.

**What's the difference between hook logs and file logs?**
- **Hook logs** (`source=hook`): Captured at the `write()` syscall. Have PID+TID context. Get trace correlation automatically (~97% correlation rate).
- **File logs** (`source=file`): Read from log files via file tailing. No PID/TID context. Cannot be correlated to traces (0% correlation rate).

---

## Quick Start

### Build

```bash
# From olly-v2/
make all              # Build libolly.so + olly binary
make test             # Run tests with race detector
```

### Deploy to AWS EC2

```bash
# 1. Cross-compile for Linux
deploy/build.sh

# 2. Provision EC2 (first time only)
cd deploy/terraform && terraform apply

# 3. Deploy everything (binary, configs, libolly.so, demo app, OTEL collector)
deploy/deploy.sh

# 4. Generate traffic
deploy/generate_traffic.sh

# 5. Verify output
deploy/verify.sh
```

### Run Locally (Linux only, requires root)

```bash
make run   # builds + runs with LD_PRELOAD
```

---

## Architecture

### Wire Protocol

The C hook library (`libolly.c`) communicates with the Go agent over a Unix DGRAM socket using a 32-byte binary header:

```
Offset  Size  Field
0       1     msg_type (1=CONNECT, 2=DATA_OUT, 3=DATA_IN, 4=CLOSE, 5=SSL_OUT, 6=SSL_IN, 7=ACCEPT, 8=LOG_WRITE)
1       3     _reserved (padding)
4       4     pid
8       4     tid
12      4     fd
16      4     payload_len
20      4     _reserved
24      8     timestamp_ns
--- 32 bytes header + payload ---
```

### Message Types

| Type | Value | Description |
|------|-------|-------------|
| CONNECT | 1 | App connected to remote (outbound, CLIENT spans) |
| DATA_OUT | 2 | Data sent on a socket |
| DATA_IN | 3 | Data received on a socket |
| CLOSE | 4 | Connection closed |
| SSL_OUT | 5 | Data sent via SSL_write |
| SSL_IN | 6 | Data received via SSL_read |
| ACCEPT | 7 | App accepted a connection (inbound, SERVER spans) |
| LOG_WRITE | 8 | App wrote to stdout/stderr/file (R6 log capture) |

### Span Generation

```
ACCEPT fd=5 from 10.0.0.1:45000 → local :5000   → creates SERVER span
  DATA_IN  fd=5  "GET /users HTTP/1.1..."         → records request
  DATA_OUT fd=5  "HTTP/1.1 200 OK..."             → records response
  CONNECT  fd=6  to 10.0.0.2:5432                 → creates CLIENT span (child of SERVER)
    DATA_OUT fd=6  "SELECT * FROM users"           → records DB query
    DATA_IN  fd=6  "<result rows>"                 → records DB response
  CLOSE fd=6                                       → completes CLIENT span
CLOSE fd=5                                         → completes SERVER span
```

### Log-Trace Correlation (R6)

```
App calls write(fd=1, "INFO: user logged in\n", 21)
    |
    v
libolly.c write() hook
    ├── fd is tracked socket? → normal network I/O path
    └── fd is stdout/stderr/regular file? → send MSG_LOG_WRITE(PID=1234, TID=5678, data)
                                                |
                                                v
Agent processHookLog()
    ├── Binary filter: skip if >10% non-printable bytes
    ├── Split on \n into individual lines
    ├── Parse each line (auto-detect: JSON, syslog, plain text)
    ├── Override PID/TID from syscall context (the key advantage)
    └── Set Source="hook", send to logCh
            |
            v
Correlation Engine: lookup PID+TID → active span → inject trace_id/span_id
            |
            v
OTLP Export: log record with top-level traceId + spanId fields
```

**Log FD Cache**: libolly.c maintains a 256-entry hash table to classify file descriptors. stdout/stderr are always captured. Regular files (detected via `fstat()`) are cached. Socket fds, the agent socket, and urandom fd are excluded. Cache is invalidated on `close()`.

---

## Configuration

### Multi-Config Mode (recommended)

```bash
olly --config-dir deploy/configs/
```

Loads `base.yaml` + `traces.yaml` + `metrics.yaml` + `logs.yaml` + `profiles.yaml`. Changes are auto-detected via fsnotify and applied without restart.

### Key Config Options

**base.yaml** — common settings:
```yaml
hook:
  enabled: true
  socket_path: /var/run/olly/hook.sock
  on_demand: true        # start dormant, activate with: olly trace start
  log_capture: true      # R6: capture write() to stdout/stderr/files (default: true)
```

**On-demand tracing**: When `on_demand: true`, the agent starts dormant. Activate/deactivate tracing at runtime:
```bash
olly trace start              # activate all hooked processes
olly trace stop               # deactivate (zero overhead when dormant)
olly trace status             # check current state
```

This uses a shared memory control file (`/var/run/olly/control`). The C hook library checks a single byte via mmap — costs 0.3-1ns per syscall when dormant.

---

## Grafana Cloud Setup

### OTEL Collector Configuration

The OTEL Collector (`deploy/otel-collector.yaml`) routes telemetry to Grafana Cloud:

```
Olly Agent → gRPC :4317 → OTEL Collector → OTLP/HTTP → Grafana Cloud
                                                          ├── Tempo  (traces)
                                                          ├── Loki   (logs)
                                                          └── Mimir  (metrics)
```

The config uses:
- `basicauth/grafana_cloud` extension for authentication
- `otlphttp/grafana_cloud` exporter to `otlp-gateway-prod-us-east-0.grafana.net/otlp`
- `resourcedetection` processor to add host metadata
- `batch` processor for efficient export

### Log-Trace Correlation in Grafana

For the Loki-to-Tempo link to work in Grafana Explore, the **Tempo datasource** needs:
- **Trace to logs**: enabled, pointing to Loki datasource
- **Filter by trace ID**: **must be enabled** (this is the key setting)
- **Filter by span ID**: enabled

For the Tempo-to-Loki link, the **Loki datasource** needs a derived field:
- **Matcher type**: `label`
- **Matcher regex**: `[tT]race_?[iI][dD]`
- **Internal link**: Tempo datasource

**If you're using Grafana Cloud provisioned datasources** (read-only), update via the Grafana UI:
1. Go to Connections > Data Sources > your Tempo datasource
2. Scroll to "Trace to logs"
3. Enable "Filter by trace ID" and "Filter by span ID"
4. Save

### Querying in Grafana Explore

**View hook-correlated logs:**
```
{service_name="olly-agent"} | source = `hook`
```

**View logs for a specific trace:**
```
{service_name="olly-agent"} | trace_id = `<your-trace-id>`
```

**View all traces:**
Explore > Tempo > Search > service.name = olly-agent

---

## Project Structure

```
olly-v2/
├── cmd/olly/main.go              # CLI entrypoint
├── pkg/
│   ├── agent/agent.go            # Main orchestrator
│   ├── hook/
│   │   ├── c/libolly.c           # C hook library (LD_PRELOAD)
│   │   ├── protocol.go           # Wire protocol constants + parser
│   │   ├── manager.go            # Unix socket listener + dispatch
│   │   ├── injector.go           # Process injection helper
│   │   └── control.go            # On-demand tracing control
│   ├── conntrack/tracker.go      # fd → connection metadata
│   ├── reassembly/
│   │   ├── stream.go             # Per-connection byte buffer
│   │   └── request.go            # Request/response pair matching
│   ├── protocol/                 # Protocol parsers
│   │   ├── http.go
│   │   ├── postgres.go
│   │   ├── mysql.go
│   │   ├── redis.go
│   │   ├── grpc.go
│   │   ├── dns.go
│   │   └── mongodb.go
│   ├── traces/processor.go       # RequestPair → OTEL Span
│   ├── correlation/engine.go     # PID+TID log-trace linking
│   ├── logs/
│   │   ├── collector.go          # File tailing + routing
│   │   ├── parser.go             # Auto-detect log format
│   │   └── record.go             # LogRecord with trace context
│   ├── metrics/collector.go      # Host + process + RED metrics
│   ├── export/
│   │   ├── manager.go            # Export orchestrator
│   │   └── otlp.go               # OTLP gRPC exporter
│   ├── config/
│   │   ├── config.go             # YAML loading + validation
│   │   └── watcher.go            # fsnotify auto-reload
│   ├── discovery/discovery.go    # Service name auto-detection
│   └── servicemap/generator.go   # Service dependency graph
├── deploy/
│   ├── build.sh                  # Cross-compile + tarball
│   ├── deploy.sh                 # EC2 deployment
│   ├── generate_traffic.sh       # Synthetic load generator
│   ├── verify.sh                 # Output verification
│   ├── otel-collector.yaml       # Grafana Cloud collector config
│   ├── configs/                  # Multi-config YAML files
│   │   ├── base.yaml
│   │   ├── traces.yaml
│   │   ├── metrics.yaml
│   │   ├── logs.yaml
│   │   └── profiles.yaml
│   ├── demo-app/                 # Flask + Go demo for testing
│   │   ├── app.py
│   │   ├── order-service/main.go
│   │   └── init_db.sql
│   └── terraform/                # AWS EC2 provisioning
├── REQUIREMENTS.md               # OTEL compliance requirements
├── FIXES.md                      # Issue tracking
└── CLAUDE.md                     # AI development context
```

---

## Deployment Notes

### Prerequisites on EC2
- Amazon Linux 2023 (t3.small or larger)
- `gcc` for compiling libolly.so (C code needs target glibc, cannot cross-compile)
- PostgreSQL for demo database
- Python 3 + pip for Flask demo app
- OTEL Collector Contrib (`otelcol-contrib`) for telemetry routing

### Important: Startup Order
1. **Olly agent** starts first (creates `/var/run/olly/hook.sock`)
2. **Order service** starts (Go binary, no LD_PRELOAD needed for Go — Go uses raw syscalls)
3. **Demo app** starts with `LD_PRELOAD=/opt/olly/libolly.so` (Python uses libc, hooks work)
4. **Activate tracing**: `olly trace start` (if `on_demand: true` in config)

### Important: Go Apps and LD_PRELOAD
Go binaries use raw syscalls instead of libc. **LD_PRELOAD hooks do NOT intercept Go I/O.** To trace Go services, they need to be the *target* of requests from hooked services (the hook captures the outbound side). Cross-service tracing works because the Python app's outbound HTTP to the Go service is captured by libolly.c on the Python side.

### Rebuilding After Code Changes

```bash
# Full rebuild + redeploy
cd olly-v2
deploy/build.sh                  # cross-compile
deploy/deploy.sh                 # upload + install + restart

# Or just the C hook library (on EC2):
ssh ec2-user@<IP>
gcc -shared -fPIC -O2 -o /opt/olly/libolly.so /tmp/olly-deploy/libolly.c -ldl -lpthread
# Then restart the demo app (it picks up libolly.so on next LD_PRELOAD load)
```

---

## OTEL Compliance Status

### Completed

| Req | Description | Phase |
|-----|-------------|-------|
| R1.1 | traceparent injection in libolly.c | Phase 1 |
| R1.2 | tracestate extraction + propagation | Phase 2 |
| R1.5 | Sampled flag (always 03 = sampled+random) | Phase 1 |
| R2.1 | HTTP semconv migration (http.request.method, etc.) | Phase 2 |
| R2.2 | DB semconv migration (db.query.text, db.namespace) | Phase 2 |
| R2.3 | Span kind SERVER vs CLIENT via direction | Phase 1 |
| R3.1 | SeverityNumber + ObservedTimestamp in logs | Phase 1 |
| R4.1 | 12 resource attributes (service.name, host.name, etc.) | Phase 1 |
| R5.1 | http.server.request.duration histogram | Phase 2 |
| R5.2 | Histogram +Inf overflow bucket | Phase 2 |
| R5.4 | CPU label fix | Phase 2 |
| R5.5 | Network errors by direction | Phase 2 |
| R6 | Log-trace correlation via write() hook | Phase 3 |

### Remaining

| Req | Description | Phase |
|-----|-------------|-------|
| R4.2 | Per-service resource attribution | Phase 3 |
| R7.2 | HTTP/2 header injection | Phase 4 |
| R7.3 | SQL comment injection | Phase 4 |
| R8 | gRPC metadata + W3C Baggage | Phase 4 |

---

## Testing

```bash
make test                    # all tests with race detector
go test -v ./pkg/hook/...    # wire protocol + dispatch tests
go test -v ./pkg/agent/...   # hook log processing tests
go test -v ./pkg/config/...  # config parsing tests
```

### Test Coverage for R6 (Log-Trace Correlation)

- `pkg/hook/protocol_test.go` — MsgLogWrite constant, parsing, type detection
- `pkg/hook/manager_test.go` — Dispatch to OnLogWrite callback, nil safety, empty payload
- `pkg/agent/agent_test.go` — processHookLog: basic, multiline, binary filter, empty lines, JSON, PID override, channel full
- `pkg/config/config_test.go` — LogCaptureEnabled default/true/false

### Verified on EC2

- 165 spans, 105 traces, proper SERVER-CLIENT parent-child linking
- 382 hook logs, 97% correlated to traces
- 322 file logs, 0% correlated (expected — no PID/TID context)
- All 10 unique trace IDs from hook logs found in Grafana Cloud Tempo
- 50 hook logs in Grafana Cloud Loki, 100% with trace_id
