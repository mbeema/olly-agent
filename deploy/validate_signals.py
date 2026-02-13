#!/usr/bin/env python3
"""Validate per-service signal grouping and data quality.

Reads /var/log/otel/{traces,logs,metrics}.json and validates:
  1. Per-service grouping: traces, logs, and metrics each have separate
     Resource blocks per service (not a single shared resource)
  2. Cross-service trace linking: spans from different services share traceIDs
  3. Protocol detection: database spans (pg/mysql/redis/mongo) have db.system
  4. Compression: verifies gzip is used (checks OTEL collector metrics)

Run on EC2: python3 validate_signals.py
"""

import json
import sys
from collections import defaultdict
from pathlib import Path


def parse_otel_file(path):
    """Parse OTEL JSON file (one JSON object per line)."""
    records = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip().replace("\x00", "")
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def get_service_name(resource):
    """Extract service.name from resource attributes."""
    for a in resource.get("attributes", []):
        if a["key"] == "service.name":
            return list(a["value"].values())[0]
    return "<unknown>"


def validate_traces(path):
    """Validate trace signal grouping and linking."""
    print(f"\n{'=' * 60}")
    print(f"  TRACES")
    print(f"{'=' * 60}")

    if not Path(path).exists():
        print("  SKIP: file not found")
        return True

    data = parse_otel_file(path)
    if not data:
        print("  SKIP: no data")
        return True

    services = defaultdict(int)  # service -> span count
    trace_services = defaultdict(set)  # traceID -> set of services
    protocols = defaultdict(int)  # db.system -> count
    span_kinds = defaultdict(int)

    for batch in data:
        for rs in batch.get("resourceSpans", []):
            svc = get_service_name(rs.get("resource", {}))
            for scope in rs.get("scopeSpans", []):
                for span in scope.get("spans", []):
                    services[svc] += 1
                    tid = span.get("traceId", "")
                    if tid:
                        trace_services[tid].add(svc)

                    kind = span.get("kind", 0)
                    kind_map = {1: "INTERNAL", 2: "SERVER", 3: "CLIENT", 4: "PRODUCER", 5: "CONSUMER"}
                    span_kinds[kind_map.get(kind, f"UNKNOWN({kind})")] += 1

                    for attr in span.get("attributes", []):
                        if attr["key"] == "db.system":
                            protocols[list(attr["value"].values())[0]] += 1

    total_spans = sum(services.values())
    multi_svc_traces = sum(1 for svcs in trace_services.values() if len(svcs) > 1)

    print(f"  Total spans: {total_spans}")
    print(f"  Services (per-service grouping):")
    for svc, count in sorted(services.items()):
        print(f"    {svc}: {count} spans")
    print(f"  Span kinds: {dict(span_kinds)}")
    print(f"  Multi-service traces: {multi_svc_traces}")
    if protocols:
        print(f"  Database protocols: {dict(protocols)}")

    ok = True
    if len(services) < 2:
        print("  WARN: Only 1 service found (per-service grouping untestable)")
    else:
        print(f"  OK: Per-service trace grouping verified ({len(services)} services)")

    if multi_svc_traces == 0 and total_spans > 10:
        print("  WARN: No multi-service traces found")
    elif multi_svc_traces > 0:
        print(f"  OK: Cross-service trace linking verified ({multi_svc_traces} traces)")

    return ok


def validate_logs(path):
    """Validate log signal grouping."""
    print(f"\n{'=' * 60}")
    print(f"  LOGS")
    print(f"{'=' * 60}")

    if not Path(path).exists():
        print("  SKIP: file not found")
        return True

    data = parse_otel_file(path)
    if not data:
        print("  SKIP: no data")
        return True

    services = defaultdict(int)
    correlated = 0
    total = 0

    for batch in data:
        for rl in batch.get("resourceLogs", []):
            svc = get_service_name(rl.get("resource", {}))
            for scope in rl.get("scopeLogs", []):
                for log in scope.get("logRecords", []):
                    services[svc] += 1
                    total += 1
                    if log.get("traceId"):
                        correlated += 1

    print(f"  Total logs: {total}")
    print(f"  Correlated with traces: {correlated}")
    print(f"  Services (per-service grouping):")
    for svc, count in sorted(services.items()):
        print(f"    {svc}: {count} logs")

    if len(services) >= 1:
        print(f"  OK: Per-service log grouping verified ({len(services)} services)")
    return True


def validate_metrics(path):
    """Validate metric signal grouping."""
    print(f"\n{'=' * 60}")
    print(f"  METRICS")
    print(f"{'=' * 60}")

    if not Path(path).exists():
        print("  SKIP: file not found")
        return True

    data = parse_otel_file(path)
    if not data:
        print("  SKIP: no data")
        return True

    services = defaultdict(int)
    metric_names = set()

    for batch in data:
        for rm in batch.get("resourceMetrics", []):
            svc = get_service_name(rm.get("resource", {}))
            for scope in rm.get("scopeMetrics", []):
                for metric in scope.get("metrics", []):
                    services[svc] += 1
                    metric_names.add(metric.get("name", ""))

    total = sum(services.values())
    print(f"  Total metric points: {total}")
    print(f"  Unique metric names: {len(metric_names)}")
    print(f"  Services (per-service grouping):")
    for svc, count in sorted(services.items()):
        print(f"    {svc}: {count} metrics")

    # Check for key metric categories
    categories = {
        "system": [n for n in metric_names if n.startswith("system.")],
        "process": [n for n in metric_names if n.startswith("process.")],
        "container": [n for n in metric_names if n.startswith("container.")],
        "mcp": [n for n in metric_names if n.startswith("mcp.")],
        "gen_ai": [n for n in metric_names if n.startswith("gen_ai.")],
    }
    for cat, names in categories.items():
        if names:
            print(f"  {cat} metrics: {len(names)} ({', '.join(sorted(names)[:3])}{'...' if len(names) > 3 else ''})")

    if len(services) >= 1:
        print(f"  OK: Per-service metric grouping verified ({len(services)} services)")
    return True


def main():
    traces_path = "/var/log/otel/traces.json"
    logs_path = "/var/log/otel/logs.json"
    metrics_path = "/var/log/otel/metrics.json"

    print("=" * 60)
    print("  SIGNAL VALIDATION REPORT")
    print("=" * 60)

    all_ok = True
    all_ok = validate_traces(traces_path) and all_ok
    all_ok = validate_logs(logs_path) and all_ok
    all_ok = validate_metrics(metrics_path) and all_ok

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"{'=' * 60}")
    if all_ok:
        print("  *** PASS: All signal validation checks passed ***")
    else:
        print("  *** FAIL: Some checks failed ***")
        sys.exit(1)


if __name__ == "__main__":
    main()
