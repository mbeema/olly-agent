# Olly — Zero-Instrumentation Observability Agent

Olly is a single Go agent that uses **eBPF** to collect distributed traces, logs, metrics, and continuous profiles from any application — **without code changes, SDK imports, or application restarts**.

Deploy one agent. See everything. Change nothing.

```
Your App (unmodified, any language)
        │
        │  eBPF hooks in the kernel
        ▼
┌─────────────────────────────────────────────────────┐
│  Olly Agent                                         │
│                                                     │
│  Traces ─── 7 protocol parsers, cross-service links │
│  Logs ───── file tailing + write() hook capture     │
│  Metrics ── host, process, container, request       │
│  Profiles ─ on-demand CPU + memory profiling        │
│                                                     │
│  PII Redaction │ Sampling │ Health Server            │
└────────────────┴──────────┴─────────────────────────┘
        │
        ▼  OTLP (gRPC / HTTP)
  Any OpenTelemetry Backend
  (Grafana Cloud, Jaeger, Datadog, Elastic, etc.)
```

## Why Olly

- **Zero instrumentation** — No code changes. No SDKs. Works with compiled binaries, legacy apps, third-party software.
- **All four signals** — Traces, logs, metrics, profiles from a single agent. Not just traces like Beyla.
- **7 protocol parsers** — HTTP, gRPC, PostgreSQL, MySQL, Redis, MongoDB, DNS — auto-detected from network traffic.
- **Cross-service distributed traces** — BPF sk_msg injects W3C traceparent headers at the TCP layer. Bidirectional stitcher as fallback.
- **On-demand profiling** — Zero overhead when idle. Trigger CPU/memory profiles without restarting anything.
- **Production-ready** — Health server, PII redaction, trace sampling, log rate limiting, hot config reload.

## Quick Start

### Build

```bash
make build            # Build Go binary
make test             # Run tests with race detector
make build-linux      # Cross-compile for Linux amd64
```

### Run (Linux, requires root for eBPF)

```bash
# Single config file
sudo ./bin/olly --config configs/olly.yaml

# Multi-config directory (with hot reload)
sudo ./bin/olly --config-dir deploy/configs/
```

### Deploy to AWS EC2

```bash
deploy/build.sh                          # Cross-compile
cd deploy/terraform && terraform apply   # Provision EC2
deploy/deploy.sh                         # Upload + install
deploy/generate_traffic.sh               # Generate demo traffic
deploy/verify.sh                         # Verify output
```

### Docker

```bash
make docker
docker run --privileged --pid=host --net=host olly:latest
```

### Kubernetes (Helm)

```bash
helm install olly deploy/helm/olly/
```

Deploys as a DaemonSet with privileged access, health probes, and RBAC.

### Systemd

```bash
sudo make install     # Installs binary, configs, systemd service
systemctl start olly
```

## Distributed Tracing

### Protocol Support

| Protocol | Captured Attributes |
|----------|-------------------|
| HTTP/1.1 | Method, path, status, headers, query params |
| gRPC | Service, method, status code |
| PostgreSQL | Query text, operation, table |
| MySQL | Query text, operation |
| Redis | Command, key |
| MongoDB | Operation, collection, database |
| DNS | Query name, record type, response code |

### Cross-Service Trace Propagation

Two mechanisms work together for end-to-end distributed traces:

1. **BPF sk_msg injection** — Automatically injects `traceparent` headers into outbound HTTP at the TCP layer. The application never sees it.
2. **Bidirectional stitcher** — When injection isn't possible (HTTPS, non-HTTP), matches CLIENT and SERVER spans by timestamp + method + path.

Verified end-to-end on EC2 (Flask + Go + PostgreSQL):

```
curl (CLIENT)
  └→ Flask (SERVER)
       └→ Flask (CLIENT)
            └→ order-service (SERVER)
                 └→ PostgreSQL QUERY
```

5 spans, 1 trace ID, correct parent-child chain. Zero code changes to any service.

### Trace Sampling

- Deterministic head-based sampling (hash of traceID)
- Configurable rate: 0.0–1.0 (default: 1.0 = keep all)
- Always keeps error spans regardless of sample rate

## Log Collection

| Method | How It Works |
|--------|-------------|
| File tailing | fsnotify inotify watch with glob patterns |
| eBPF write() hook | kprobe captures stdout/stderr with PID/TID |
| Security audit | Parses auditd + auth.log (login, sudo, privilege escalation) |

Features: format auto-detection (JSON/syslog/plain), log-trace correlation via PID+TID, sampling, rate limiting, PII redaction.

## Metrics

### Host Metrics (100+)

- **CPU** — Utilization %, 8-state breakdown (user, system, idle, nice, iowait, irq, softirq, steal)
- **Memory** — 7 states (used, free, available, cached, buffered, shared, slab), swap
- **Disk** — Usage per partition, inodes, I/O (bytes, ops, time, merges) per device
- **Network** — Bytes, packets, errors, drops per interface
- **System** — Load average, open FDs, TCP states, uptime, context switches, process counts

### Process Metrics (Per-PID)

CPU %, memory (RSS/VMS), threads, open FDs, disk I/O, context switches. PIDs auto-discovered from network activity.

### Container Metrics (cgroup v2)

CPU (usage, throttle, limit), memory (usage, RSS, cache, OOM kills, limit), disk I/O. Reads cgroupfs directly — no Docker socket needed.

### Request Metrics

HTTP request rate, latency histograms (P50/P95/P99), status code breakdown. Per-service, per-endpoint.

## Continuous Profiling

On-demand with zero idle overhead:

```bash
olly profile start --type=cpu --duration=30s --pid=1234
olly profile start --type=memory --pid=1234
```

- **CPU** — perf_event_open at 99Hz with kernel+user stacks
- **Memory** — /proc/smaps_rollup parsing
- **Export** — Pyroscope (Grafana Cloud compatible) or OTLP

## Privacy & Security

### PII Redaction

Built-in rules for credit cards, SSN, authorization headers, passwords, SQL passwords. Applied to all logs and span attributes before export. Configurable custom rules.

### SQL Normalization

```sql
-- Before:  SELECT * FROM users WHERE id = 42 AND name = 'Alice'
-- After:   SELECT * FROM users WHERE id = ? AND name = ?
```

### Sensitive Header Redaction

Automatically redacts: Authorization, Cookie, Set-Cookie, X-Api-Key, Proxy-Authorization.

## Production Safety

| Feature | Details |
|---------|---------|
| Health server | `/health` (liveness), `/ready` (readiness), `/metrics` (Prometheus) on `:8686` |
| Graceful shutdown | 30s timeout, force exit if stuck |
| Self-monitoring | Spans/logs/metrics received, exported, dropped counters |
| Resource limits | Systemd: 512M memory, 50% CPU, unlimited memlock |
| Graceful degradation | eBPF unavailable → socket provider → stub provider |
| Hot config reload | fsnotify-based, no restart needed |
| On-demand tracing | `olly trace start/stop` — zero overhead when inactive |

## Configuration

### Multi-Config Directory (recommended)

```bash
olly --config-dir /etc/olly/
```

Files: `base.yaml`, `traces.yaml`, `metrics.yaml`, `logs.yaml`, `profiles.yaml`. Changes auto-detected and applied without restart.

### Environment Variable Overrides

```bash
OLLY_SERVICE_NAME=my-app
OLLY_LOG_LEVEL=debug
OLLY_TRACING_SAMPLING_RATE=0.1
OLLY_EXPORTERS_OTLP_ENDPOINT=otel-collector:4317
OLLY_HEALTH_PORT=:9090
```

### Service Discovery

Auto-detects service names from environment variables (`OTEL_SERVICE_NAME`, `DD_SERVICE`), command-line parsing (Java JARs, Python modules, Go binaries), and port-based mapping (3306=mysql, 5432=postgresql, etc.).

## eBPF Programs

| Program | Type | Purpose |
|---------|------|---------|
| sys_connect | kprobe | Track outbound connections (CLIENT) |
| sys_accept/accept4 | kprobe | Track inbound connections (SERVER) |
| sys_read/write | kprobe | Capture network data (256 bytes max) |
| sys_close | kprobe | Cleanup connection state |
| SSL_read/write | uprobe | Capture plaintext before TLS encryption |
| sockops | cgroup/sock_ops | Populate sockhash for outbound TCP |
| sk_msg | sk_msg | Inject traceparent into outbound HTTP |

BPF maps: conn_map (16K), thread_trace_ctx (8K), sock_ops_map (16K sockhash), ring buffer (4MB zero-copy).

## Project Structure

```
olly/
├── cmd/olly/main.go                # CLI entrypoint + graceful shutdown
├── pkg/
│   ├── agent/agent.go              # Main orchestrator
│   ├── hook/
│   │   ├── ebpf/                   # eBPF provider (Linux)
│   │   │   ├── bpf/olly.bpf.c     # BPF C programs
│   │   │   ├── loader.go           # BPF program loader
│   │   │   ├── ringbuf.go          # Ring buffer reader
│   │   │   ├── ssl.go              # SSL uprobe attachment
│   │   │   └── provider_linux.go   # eBPF hook provider
│   │   ├── manager.go              # Socket-based hook provider
│   │   ├── provider.go             # HookProvider interface
│   │   └── control.go              # On-demand tracing control
│   ├── conntrack/tracker.go        # fd → connection metadata
│   ├── reassembly/                 # Stream reassembly + pair matching
│   ├── protocol/                   # HTTP, gRPC, PG, MySQL, Redis, MongoDB, DNS
│   ├── traces/
│   │   ├── processor.go            # RequestPair → OTEL Span
│   │   ├── stitcher.go             # Cross-service trace stitching
│   │   ├── sampler.go              # Head-based trace sampling
│   │   └── span.go                 # Span model + TraceParent
│   ├── logs/
│   │   ├── collector.go            # File tailing + sampling + rate limiting
│   │   ├── audit.go                # Security audit log parser
│   │   └── parser.go               # Auto-detect log format
│   ├── metrics/
│   │   ├── collector.go            # Host metrics (CPU, memory, disk, network)
│   │   ├── system.go               # System metrics (load, FDs, TCP, disk IO)
│   │   ├── process.go              # Per-process metrics
│   │   ├── container.go            # Container metrics (cgroup v2)
│   │   └── request.go              # Request metrics (histograms)
│   ├── profiling/
│   │   ├── profiler.go             # Profiler interface (on-demand)
│   │   ├── profiler_linux.go       # perf_event + smaps
│   │   └── profiler_stub.go        # Non-Linux no-op
│   ├── correlation/engine.go       # PID+TID log-trace linking
│   ├── export/
│   │   ├── manager.go              # Export orchestrator
│   │   ├── otlp.go                 # OTLP gRPC/HTTP (per-service ResourceSpans)
│   │   ├── pyroscope.go            # Pyroscope profile export
│   │   └── stdout.go               # Debug exporter
│   ├── health/
│   │   ├── server.go               # /health, /ready, /metrics endpoints
│   │   └── stats.go                # Self-monitoring counters
│   ├── redact/
│   │   ├── redactor.go             # PII redaction pipeline
│   │   └── normalize.go            # SQL query normalization
│   ├── config/
│   │   ├── config.go               # YAML + env var overrides
│   │   └── watcher.go              # fsnotify hot reload
│   ├── discovery/discovery.go      # Service name auto-detection
│   └── servicemap/generator.go     # Service dependency graph
├── deploy/
│   ├── configs/                    # Multi-config YAML files
│   ├── helm/olly/                  # Helm chart (DaemonSet + RBAC)
│   ├── olly.service                # Systemd unit file
│   ├── install.sh                  # Install script
│   ├── terraform/                  # AWS EC2 provisioning
│   └── demo-app/                   # Flask + Go demo
├── docs/
│   ├── current-state.md            # Complete feature inventory
│   ├── gap-analysis.md             # Expert comparison vs Datadog/Dynatrace
│   └── tracing.md                  # Distributed tracing deep-dive
├── Dockerfile                      # Multi-stage container build
├── Makefile                        # Build, test, docker, helm, install
└── LICENSE                         # BSL 1.1
```

## Comparison

| Capability | Olly | Grafana Beyla | Datadog | Dynatrace |
|---|---|---|---|---|
| Approach | eBPF kernel-level | eBPF kernel-level | Library injection | Code injection |
| Languages | Any | Any | Language-specific | Language-specific |
| Signals | L + M + T + P | T + M | L + M + T + P | L + M + T + P |
| Protocol parsers | 7 | 2-3 | 10+ | 10+ |
| Cross-service traces | sk_msg + stitcher | TC filter | Library hooks | Code hooks |
| DB query capture | PG, MySQL, Redis, Mongo | No | Yes | Yes |
| Log collection | File + eBPF hook | No | Yes | Yes |
| Continuous profiling | On-demand, zero idle cost | No | Yes | Yes |
| Container metrics | cgroupfs direct | No | Yes | Yes |
| PII redaction | Built-in | No | Yes | Yes |
| Open source | Yes (BSL 1.1) | Yes (Apache 2.0) | No | No |
| Code changes | **Zero** | **Zero** | Some | Some |

## Platform Support

| Platform | Traces | Logs | Metrics | Profiles |
|----------|--------|------|---------|----------|
| Linux (kernel 5.8+ with BTF) | Full (eBPF) | Full | Full | Full |
| macOS | Stub | File tailing | Host metrics | Stub |

## License

Copyright 2024-2026 Madhukar Beema. All rights reserved.

Licensed under the [Business Source License 1.1](LICENSE). You may use this software for non-production purposes. Production use is permitted as long as you are not offering it as a competing commercial service. After 4 years, each release converts to Apache 2.0.
