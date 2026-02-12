<!-- Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved. -->
<!-- Author: Madhukar Beema, Distinguished Engineer -->

# Olly Agent — Current State & Feature Inventory

> Last updated: February 2026

## Overview

Olly is a **zero-instrumentation observability agent** written in Go. It uses eBPF to collect distributed traces, logs, metrics, and continuous profiles from any application — without code changes, SDK imports, or application restarts.

One agent. All four signals. Zero code changes.

---

## Architecture

```
                     eBPF Programs (kernel space)
                 ┌─────────────────────────────────┐
                 │  kprobes: connect, accept,       │
                 │           read, write, close      │
                 │  uprobes: SSL_read, SSL_write     │
                 │  sockops: TCP connection tracking  │
                 │  sk_msg:  traceparent injection    │
                 └──────────────┬────────────────────┘
                                │ ring buffer (4MB, zero-copy)
                                ▼
┌──────────────────────────────────────────────────────────────┐
│                    Olly Agent (userspace)                     │
│                                                              │
│  ┌──────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │Connection │→ │   Stream     │→ │  Protocol Parsers      │ │
│  │ Tracker   │  │ Reassembler  │  │  HTTP, gRPC, PG, MySQL │ │
│  │(dir-aware)│  │(per-conn buf)│  │  Redis, MongoDB, DNS   │ │
│  └──────────┘  └──────────────┘  └───────────┬────────────┘ │
│                                               ▼              │
│  ┌──────────────┐  ┌──────────┐  ┌────────────────────────┐ │
│  │ Log Collector │  │ Metrics  │  │   Trace Processor      │ │
│  │ (file+hook)   │  │Collector │  │  + Stitcher + Sampler  │ │
│  └──────┬───────┘  └────┬─────┘  └───────────┬────────────┘ │
│         │               │                     │              │
│         ▼               ▼                     ▼              │
│  ┌──────────────────────────────────────────────────────────┐│
│  │         PII Redactor + SQL Normalizer                    ││
│  └──────────────────────┬───────────────────────────────────┘│
│                         ▼                                    │
│  ┌──────────────────────────────────────────────────────────┐│
│  │    Export Manager (OTLP gRPC/HTTP, Stdout, Pyroscope)    ││
│  └──────────────────────────────────────────────────────────┘│
│                                                              │
│  ┌──────────┐  ┌───────────────┐  ┌───────────────────────┐ │
│  │ Health   │  │ Config Reload │  │ Service Discovery     │ │
│  │ Server   │  │ (fsnotify)    │  │ (auto, env, cmdline)  │ │
│  └──────────┘  └───────────────┘  └───────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

---

## Distributed Tracing

### Protocol Support (7 Protocols)

| Protocol | Detection | Captured Attributes |
|----------|-----------|-------------------|
| **HTTP/1.1** | Method + path + version | method, path, status, headers, query |
| **HTTP/2 + gRPC** | Frame parsing + gRPC metadata | service, method, status code |
| **PostgreSQL** | Wire protocol messages | query text, operation, table |
| **MySQL** | COM_QUERY detection | query text, operation |
| **Redis** | RESP protocol parsing | command, key |
| **MongoDB** | BSON wire protocol | operation, collection, db |
| **DNS** | UDP/TCP packet parsing | query, record type, response code |

All protocols are auto-detected from network traffic. No configuration needed.

### Cross-Service Trace Propagation

Two complementary mechanisms ensure end-to-end distributed traces:

**1. BPF sk_msg Traceparent Injection**
- eBPF `sockops` program tracks outbound TCP connections in a sockhash
- eBPF `sk_msg` program intercepts sendmsg and injects `traceparent` header
- W3C Trace Context format: `traceparent: 00-{traceID}-{spanID}-01\r\n`
- Works for HTTP traffic over plain TCP (IPv4 + IPv6)
- Zero application awareness — injection happens at the TCP layer

**2. Bidirectional Trace Stitcher (Fallback)**
- Matches outbound CLIENT spans with inbound SERVER spans
- Correlation criteria: HTTP method + URL path + timestamp (configurable window)
- Bidirectional: stores whichever span arrives first, matches when counterpart arrives
- CLIENT adopts SERVER's traceID (preserves intra-process span children)
- Activates automatically when sk_msg injection isn't possible (HTTPS, non-HTTP)

**3. Thread Context Propagation**
- PID+TID → trace context map links intra-process spans
- Inbound HTTP request creates context; outbound CLIENT spans inherit it
- PID-only fallback for Go goroutine TID mismatch
- 30-second TTL with periodic cleanup

### Verified End-to-End Chain

Tested on EC2 with Flask (Python) → order-service (Go) → PostgreSQL:

```
curl (CLIENT)
  └→ Flask (SERVER) ─── traceID: abc123
       └→ Flask (CLIENT) ─── parent: Flask SERVER spanID
            └→ order-service (SERVER) ─── parent: Flask CLIENT spanID
                 └→ PostgreSQL QUERY ─── parent: order-service SERVER spanID
```

4 spans, 1 trace ID, correct parent-child chain. Zero code changes to any service.

### Trace Sampling

- Deterministic head-based sampling (hash of traceID)
- Configurable rate: 0.0 (drop all) to 1.0 (keep all)
- Always keeps error spans regardless of sample rate
- Consistent across services (same traceID → same decision)

---

## Log Collection

### Collection Methods

| Method | How It Works | Use Case |
|--------|-------------|----------|
| **File tailing** | fsnotify inotify watch + glob patterns | Application log files |
| **eBPF write() hook** | kprobe on sys_write, captures stdout/stderr | Container stdout, apps without files |
| **Security audit** | Parses auditd + auth.log formats | Security monitoring |

### Features

- **Format auto-detection**: JSON, syslog, combined, plaintext
- **Level extraction**: TRACE, DEBUG, INFO, WARN, ERROR, FATAL
- **Log-trace correlation**: PID+TID+timestamp matching (100ms window)
- **Sampling**: Configurable rate (0.0-1.0)
- **Rate limiting**: Token bucket, max logs/second
- **PII redaction**: Applied before export
- **Rotation handling**: Follows file moves via inotify

### Security Event Classification

Events from `/var/log/audit/audit.log` and `/var/log/auth.log`:

- `login` / `login_failed` — SSH, console logins
- `sudo` — Privilege elevation
- `privilege_escalation` — setuid, capability changes
- `file_access` — Sensitive file operations
- `user_change` / `group_change` — Account modifications

---

## Metrics Collection

### Host Metrics (100+ metrics via gopsutil)

**CPU** — Utilization %, 8-state time breakdown (user, system, idle, nice, iowait, irq, softirq, steal), logical + physical core count

**Memory** — 7 states (used, free, available, cached, buffered, shared, slab), total, utilization %, swap (used/free/total/%)

**Disk** — Per-partition usage (used/free/total/%), inode metrics (total/used/free/%), I/O (read/write bytes + ops + time + merged ops) per device

**Network** — Per-interface bytes + packets (tx/rx), errors + drops (tx/rx)

**System** — Load average (1m/5m/15m, raw + normalized), open FDs, TCP connection states (ESTABLISHED, LISTEN, TIME_WAIT, etc.), uptime, context switches, process counts (running/blocked/created/total)

### Process Metrics (Per-PID)

CPU %, memory (RSS/VMS/%), threads, open FDs, disk I/O (read/write bytes + ops), context switches (voluntary + involuntary). PIDs auto-discovered from network activity.

### Container Metrics (cgroup v2, direct cgroupfs reads)

**CPU** — Usage (user + system), throttled count + time, CPU limit (quota/period)

**Memory** — Usage, RSS, cache, kernel, sock, slab, page faults (major/minor), OOM kills, memory limit, utilization %

**Disk I/O** — Read/write bytes + operations per device

No Docker socket dependency — reads `/sys/fs/cgroup` directly.

### Request Metrics (Derived from Traces)

- HTTP request rate (requests/sec)
- Latency distribution (P50, P95, P99)
- Status code breakdown (2xx, 3xx, 4xx, 5xx)
- Configurable histogram buckets
- Per-service, per-endpoint, per-method

---

## Continuous Profiling

### On-Demand Mode (Default)

Zero overhead when idle. Profile only when triggered:

```bash
olly profile start --type=cpu --duration=30s --pid=1234
```

State machine: `Idle → Active → Idle`

### Profile Types

| Type | Method | Output |
|------|--------|--------|
| CPU | `perf_event_open` at 99Hz, kernel+user stacks | pprof (gzip protobuf) |
| Memory | `/proc/<pid>/smaps_rollup` parsing | RSS breakdown |

### Export Targets

- **Pyroscope** — Direct gzip pprof upload (Grafana Cloud compatible)
- **OTLP** — OpenTelemetry Profiling format

---

## Privacy & Security

### PII Redaction Pipeline

Built-in rules (configurable, extensible):

| Rule | Pattern | Applied To |
|------|---------|-----------|
| Credit cards | 13-19 digit sequences | Logs, span attributes |
| SSN | XXX-XX-XXXX | Logs, span attributes |
| Auth headers | `Authorization: ...` | HTTP headers, span attributes |
| Passwords | `password=...`, `token=...`, `api_key=...` | Logs, span attributes |
| SQL passwords | `password='...'` | DB query attributes |

### SQL Normalization

Replaces literal values with `?` placeholders:

```sql
-- Before
SELECT * FROM users WHERE id = 42 AND name = 'Alice'
-- After
SELECT * FROM users WHERE id = ? AND name = ?
```

Handles: string literals, numbers, hex values, IN lists.

### Sensitive Header Redaction

Automatically redacts values for: `Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`, `Proxy-Authorization`

---

## Export & Integration

### OTLP (OpenTelemetry Protocol)

- **Signals**: Traces, Logs, Metrics
- **Protocols**: gRPC (default), HTTP
- **Per-service ResourceSpans**: Correct `service.name` and `process.executable.name` per service
- **Batching**: 10,000 channel capacity
- **Targets**: Grafana Cloud (Tempo, Loki, Mimir), Jaeger, Elastic, Datadog (OTLP), any OTLP-compatible backend

### Pyroscope (Profiling)

- Direct pprof upload to Pyroscope/Grafana Cloud Profiles
- Basic auth support for cloud instances

### Stdout Exporter

- Text or JSON format for debugging and local testing

### Self-Monitoring

| Endpoint | Purpose | Format |
|----------|---------|--------|
| `GET /health` | Liveness (status, version, uptime) | JSON |
| `GET /ready` | Readiness (503 during init, 200 when ready) | JSON |
| `GET /metrics` | Agent self-metrics | Prometheus text |

Tracked counters: spans/logs/metrics/profiles received, exported, dropped. Plus memory RSS, goroutine count, uptime.

---

## Configuration

### Multi-Config Directory Mode

```bash
olly --config-dir /etc/olly/
```

Files: `base.yaml`, `traces.yaml`, `metrics.yaml`, `logs.yaml`, `profiles.yaml`

Hot reload via fsnotify (500ms debounce). No restart needed.

### Environment Variable Overrides

| Variable | Effect |
|----------|--------|
| `OLLY_SERVICE_NAME` | Override service name |
| `OLLY_LOG_LEVEL` | Set log level (debug/info/warn/error) |
| `OLLY_HEALTH_PORT` | Health server port |
| `OLLY_TRACING_ENABLED` | Enable/disable tracing |
| `OLLY_LOGS_ENABLED` | Enable/disable logs |
| `OLLY_METRICS_ENABLED` | Enable/disable metrics |
| `OLLY_PROFILING_ENABLED` | Enable/disable profiling |
| `OLLY_TRACING_SAMPLING_RATE` | Trace sampling rate (0.0-1.0) |
| `OLLY_EXPORTERS_OTLP_ENDPOINT` | OTLP endpoint |

### Service Discovery

Auto-detects service names from:
1. Environment variables (`OTEL_SERVICE_NAME`, `SERVICE_NAME`, `DD_SERVICE`, `APP_NAME`)
2. Command-line parsing (Java JAR names, Python modules, Node.js scripts, Go binary names)
3. Port-based mapping (3306 → mysql, 5432 → postgresql, 6379 → redis, etc.)

---

## Deployment Options

### Systemd (Bare Metal / VMs)

```bash
sudo deploy/install.sh   # Installs binary, configs, systemd service
systemctl start olly
```

Resource limits: 512M memory, 50% CPU. Auto-restart on failure.

### Docker

```bash
docker build -t olly:latest .
docker run --privileged --pid=host --net=host olly:latest
```

Multi-stage build (Go 1.24 builder + alpine runtime).

### Kubernetes (Helm)

```bash
helm install olly deploy/helm/olly/
```

DaemonSet with: privileged security context, hostPID, hostNetwork, volume mounts for cgroupfs/bpffs/debugfs, liveness/readiness probes, RBAC (ServiceAccount + ClusterRole).

### AWS EC2 (Terraform)

```bash
cd deploy/terraform && terraform apply
deploy/deploy.sh    # SCP + install
```

---

## eBPF Programs

### Syscall Hooks (kprobes/kretprobes)

| Hook | Purpose |
|------|---------|
| `sys_connect` | Track outbound connections (CLIENT direction) |
| `sys_accept` / `sys_accept4` | Track inbound connections (SERVER direction) |
| `sys_read` / `sys_write` | Capture network data (up to 256 bytes) |
| `sys_sendto` / `sys_recvfrom` | Capture UDP data |
| `sys_close` | Cleanup connection state |

### SSL/TLS Hooks (uprobes)

| Hook | Purpose |
|------|---------|
| `SSL_set_fd` | Map SSL context → fd |
| `SSL_read` / `SSL_write` | Capture plaintext before encryption |

Auto-discovered by scanning `/proc/<pid>/maps` for `libssl.so`.

### Socket Programs

| Program | Purpose |
|---------|---------|
| `sockops` | Populate sockhash for outbound TCP (IPv4 + IPv6) |
| `sk_msg` | Inject traceparent header into outbound HTTP |

### BPF Maps

| Map | Size | Purpose |
|-----|------|---------|
| `conn_map` | 16K entries | fd → {addr, port, direction} |
| `thread_trace_ctx` | 8K entries | PID+TID → traceparent header |
| `sock_ops_map` | 16K sockhash | 4-tuple → socket for sk_msg |
| Ring buffer | 4MB | Zero-copy event streaming to userspace |

### On-Demand Tracing

```bash
olly trace start    # Activate eBPF hooks
olly trace stop     # Deactivate (zero overhead)
olly trace status   # Check current state
```

BPF `tracing_enabled` map toggle — hooks check this flag and skip capture when disabled.

---

## Production Safety

- **Graceful shutdown**: 30s timeout, force exit if stuck
- **Health checks**: Kubernetes-compatible liveness/readiness probes
- **Self-monitoring**: Prometheus metrics for all signal pipelines
- **Resource limits**: Systemd MemoryMax=512M, CPUQuota=50%, LimitMEMLOCK=infinity
- **Graceful degradation**: eBPF failure → socket provider → stub provider
- **Lock-free hot paths**: Buffered channels (10K capacity), atomic config pointer
- **Thread safety**: sync.RWMutex, per-stream mutexes, atomic counters

---

## What Olly Does NOT Require

- No application code changes
- No SDK imports or library dependencies
- No language-specific agents
- No application restarts
- No source code access
- No service mesh or sidecar proxies
- No Docker socket (for container metrics)
- No manual configuration (sensible defaults)

---

## Platform Support

| Platform | Traces | Logs | Metrics | Profiles |
|----------|--------|------|---------|----------|
| **Linux (kernel 5.8+ with BTF)** | Full (eBPF) | Full | Full | Full |
| **macOS** | Stub (no eBPF) | File tailing | Host metrics | Stub |
| **Windows** | Planned | Planned | Planned | Planned |

---

## Competitive Comparison

| Capability | Olly | Grafana Beyla | Datadog Agent | Dynatrace OneAgent |
|---|---|---|---|---|
| Approach | eBPF kernel-level | eBPF kernel-level | Library injection | Code injection |
| Languages | Any | Any | Language-specific | Language-specific |
| Signals | L + M + T + P | T + M | L + M + T + P | L + M + T + P |
| Protocol parsers | 7 | 2-3 | 10+ | 10+ |
| Cross-service traces | sk_msg + stitcher | TC/socket filter | Library hooks | Code hooks |
| DB query capture | PG, MySQL, Redis, Mongo | HTTP only | Yes | Yes |
| Log collection | File + eBPF hook | No | Yes | Yes |
| Continuous profiling | On-demand, zero idle cost | No | Yes | Yes |
| Container metrics | cgroupfs direct | No | Yes | Yes |
| Security audit logs | auditd + auth.log | No | Yes (limited) | Limited |
| PII redaction | Built-in | No | Yes | Yes |
| SQL normalization | Built-in | No | Yes | Yes |
| Health endpoints | /health, /ready, /metrics | No | Yes | Yes |
| Hot config reload | fsnotify (no restart) | No | Yes | Yes |
| Open source | Yes | Yes | No | No |
| Code changes required | **Zero** | **Zero** | Some | Some |

---

## Build & Test

```bash
make build           # Build Go binary
make test            # Run tests with race detector
make build-linux     # Cross-compile for Linux amd64
make docker          # Build Docker image
make helm-template   # Render Helm manifests
go build ./...       # Verify compilation (works on macOS without clang)
```

All tests pass on macOS with stub eBPF provider. Full E2E testing on Linux (EC2, kernel 6.1).
