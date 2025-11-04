# Olly Agent — Expert Gap Analysis

## Methodology

Compared against three production-grade observability agents:
- **Datadog Agent** (dd-agent) — market leader, full-stack APM
- **Dynatrace OneAgent** — enterprise auto-instrumentation
- **Google Cloud Ops Agent** — cloud-native, open standards

Scoring: 0-100 across 10 categories (10 pts each).

---

## Scoring Summary

| Category | Before | After | Datadog | Dynatrace | Google |
|---|---|---|---|---|---|
| Core Tracing | 8/10 | 8/10 | 9/10 | 10/10 | 7/10 |
| Metrics | 8/10 | 8/10 | 9/10 | 9/10 | 8/10 |
| Logs | 6/10 | 7/10 | 9/10 | 8/10 | 8/10 |
| Profiling | 6/10 | 6/10 | 8/10 | 9/10 | 5/10 |
| Production Safety | 3/10 | 8/10 | 9/10 | 10/10 | 8/10 |
| Installation/Deploy | 2/10 | 7/10 | 10/10 | 9/10 | 8/10 |
| Data Pipeline | 4/10 | 7/10 | 9/10 | 9/10 | 7/10 |
| Security/Compliance | 5/10 | 7/10 | 9/10 | 10/10 | 8/10 |
| Scalability | 6/10 | 6/10 | 9/10 | 9/10 | 7/10 |
| Documentation | 7/10 | 7/10 | 10/10 | 9/10 | 8/10 |
| **Total** | **55/100** | **71/100** | **91/100** | **92/100** | **74/100** |

---

## Detailed Findings

### 1. Production Safety (3 → 8)

**Before:** No health endpoints, no self-monitoring, no graceful shutdown timeout.

**Implemented:**
- Health HTTP server (`/health`, `/ready`, `/metrics`) on `:8686`
- Graceful shutdown with 30s timeout
- Self-monitoring stats (spans/logs/metrics received/exported/dropped)
- Prometheus-format metrics endpoint

**Remaining gaps:**
- Circuit breaker for export destinations
- OOM protection (memory-based backpressure)
- Crash recovery / WAL for in-flight data

### 2. Installation & Deployment (2 → 7)

**Before:** Manual binary copy, no service management, no container support.

**Implemented:**
- Systemd service file with resource limits (512M RAM, 50% CPU)
- Install script with architecture detection
- Multi-stage Dockerfile (alpine runtime)
- Helm chart with DaemonSet, ConfigMap, RBAC, health probes

**Remaining gaps:**
- RPM/DEB packages
- Ansible/Chef/Puppet recipes
- Auto-update mechanism
- ARM64 container images

### 3. Data Pipeline (4 → 7)

**Before:** No sampling, no rate limiting, no PII redaction, no env var config.

**Implemented:**
- Head-based trace sampling (deterministic by traceID, always keeps errors)
- Log sampling and per-second rate limiting (token bucket)
- PII redaction (credit cards, SSN, auth headers, passwords)
- SQL query normalization (replaces literals with `?`)
- Environment variable config overrides (`OLLY_*` prefix)

**Remaining gaps:**
- Tail-based sampling (requires buffering full traces)
- Log-to-metric rules
- Attribute-based filtering/routing
- Data forwarding to multiple backends

### 4. Security/Compliance (5 → 7)

**Before:** Audit log collection existed but no data-plane security.

**Implemented:**
- PII redaction pipeline with configurable rules
- SQL normalization prevents leaking query parameters
- Auth header redaction in HTTP traces

**Remaining gaps:**
- mTLS for OTLP export
- Secrets management (vault integration)
- FIPS 140-2 compliance
- Data retention policies

### 5. Core Tracing (8 → 8, no change)

**Strengths:**
- eBPF-based with sk_msg traceparent injection
- Cross-service trace propagation (verified E2E)
- 7 protocol parsers (HTTP, gRPC, PG, MySQL, Redis, MongoDB, DNS)
- Proper SERVER/CLIENT span hierarchy

**Gaps vs. competition:**
- No Java/Node bytecode instrumentation (relies on network-level only)
- No distributed trace assembly (tail-based)
- No trace analytics / anomaly detection

### 6. Metrics (8 → 8, no change)

**Strengths:**
- Host (CPU/mem/disk/net), process, container (cgroup v2) metrics
- Request metrics with histogram latency buckets
- Service map generation

**Gaps:**
- No custom metric API
- No StatsD/DogStatsD receiver
- No metric aggregation/rollup

### 7. Logs (6 → 7)

**Improvements:** Sampling, rate limiting, PII redaction.

**Remaining gaps:**
- No multiline log aggregation
- No log pipeline (parse → filter → route)
- No log-to-trace linking from structured JSON logs (only PID/TID correlation)

### 8. Scalability (6 → 6, no change)

**Current design:** Single-agent, single-machine. Good for moderate workloads.

**Gaps:**
- No horizontal data sharding
- No remote configuration management
- No fleet management UI
- No adaptive sampling based on load

---

## Prioritized Roadmap (Next Phases)

### Phase 5: Reliability (Target: +5 pts)
1. Circuit breaker for OTLP export with local disk buffering
2. Memory-based backpressure (pause collection at 80% limit)
3. Crash recovery: persist in-flight spans to disk

### Phase 6: Advanced Pipeline (Target: +5 pts)
1. Tail-based sampling with trace buffer
2. Log pipeline with parse/filter/route stages
3. Custom metric API (StatsD receiver)

### Phase 7: Enterprise Features (Target: +5 pts)
1. mTLS for all external connections
2. Fleet management API
3. Remote configuration
4. Multi-backend routing

### Phase 8: Platform Coverage (Target: +5 pts)
1. RPM/DEB packages via CI
2. Windows service support
3. ARM64 builds and images
4. Kubernetes operator
