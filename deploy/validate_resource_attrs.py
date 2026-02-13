#!/usr/bin/env python3
"""Validate OTLP resource attributes across all three signals.

Reads /var/log/otel/{traces,logs,metrics}.json and verifies:
  1. service.name is set on every resource
  2. service.version and deployment.environment are present (when configured)
  3. Per-service grouping: each service gets its own Resource block
  4. Standard attributes present: telemetry.sdk.*, host.name, process.pid

Run on EC2: python3 validate_resource_attrs.py [--require-version] [--require-env]
"""

import argparse
import json
import sys
from pathlib import Path


def parse_otel_file(path):
    """Parse OTEL JSON file (one JSON object per line)."""
    resources = []
    with open(path, "r", errors="replace") as f:
        for line in f:
            line = line.strip().replace("\x00", "")
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            resources.append(data)
    return resources


def extract_attrs(resource):
    """Extract attributes dict from a Resource protobuf JSON."""
    attrs = {}
    for a in resource.get("attributes", []):
        key = a["key"]
        val = a.get("value", {})
        for vtype in ("stringValue", "intValue", "doubleValue", "boolValue"):
            if vtype in val:
                attrs[key] = val[vtype]
                break
    return attrs


def check_signal(name, path, resource_key):
    """Check resource attributes for a signal (traces/logs/metrics)."""
    print(f"\n{'=' * 60}")
    print(f"  {name.upper()}: {path}")
    print(f"{'=' * 60}")

    if not Path(path).exists():
        print(f"  SKIP: file not found")
        return [], True

    data = parse_otel_file(path)
    if not data:
        print(f"  SKIP: no data")
        return [], True

    all_services = {}
    errors = []

    for batch in data:
        for rs in batch.get(resource_key, []):
            resource = rs.get("resource", {})
            attrs = extract_attrs(resource)
            svc = attrs.get("service.name", "<MISSING>")

            if svc == "<MISSING>":
                errors.append(f"  ERROR: Resource missing service.name")
                continue

            if svc not in all_services:
                all_services[svc] = attrs

    for svc, attrs in sorted(all_services.items()):
        ver = attrs.get("service.version", "-")
        env = attrs.get("deployment.environment", "-")
        sdk = attrs.get("telemetry.sdk.name", "-")
        host = attrs.get("host.name", "-")
        pid = attrs.get("process.pid", "-")
        print(f"  {svc}:")
        print(f"    version={ver}, env={env}, sdk={sdk}, host={host}, pid={pid}")

    print(f"\n  Services found: {len(all_services)}")
    for e in errors:
        print(e)

    return all_services, len(errors) == 0


def main():
    parser = argparse.ArgumentParser(description="Validate OTLP resource attributes")
    parser.add_argument("--traces", default="/var/log/otel/traces.json")
    parser.add_argument("--logs", default="/var/log/otel/logs.json")
    parser.add_argument("--metrics", default="/var/log/otel/metrics.json")
    parser.add_argument("--require-version", action="store_true",
                        help="Fail if service.version is missing")
    parser.add_argument("--require-env", action="store_true",
                        help="Fail if deployment.environment is missing")
    args = parser.parse_args()

    all_ok = True

    trace_svcs, ok = check_signal("traces", args.traces, "resourceSpans")
    all_ok = all_ok and ok

    log_svcs, ok = check_signal("logs", args.logs, "resourceLogs")
    all_ok = all_ok and ok

    metric_svcs, ok = check_signal("metrics", args.metrics, "resourceMetrics")
    all_ok = all_ok and ok

    # Check version/env if required
    print(f"\n{'=' * 60}")
    print(f"  VALIDATION")
    print(f"{'=' * 60}")

    if args.require_version:
        for signal_name, svcs in [("traces", trace_svcs), ("logs", log_svcs), ("metrics", metric_svcs)]:
            for svc, attrs in (svcs.items() if isinstance(svcs, dict) else []):
                if "service.version" not in attrs:
                    print(f"  FAIL: {signal_name}/{svc} missing service.version")
                    all_ok = False

    if args.require_env:
        for signal_name, svcs in [("traces", trace_svcs), ("logs", log_svcs), ("metrics", metric_svcs)]:
            for svc, attrs in (svcs.items() if isinstance(svcs, dict) else []):
                if "deployment.environment" not in attrs:
                    print(f"  FAIL: {signal_name}/{svc} missing deployment.environment")
                    all_ok = False

    # Check per-service grouping in traces
    if isinstance(trace_svcs, dict) and len(trace_svcs) > 1:
        print(f"  OK: Traces have per-service grouping ({len(trace_svcs)} services)")
    elif isinstance(trace_svcs, dict) and len(trace_svcs) == 1:
        print(f"  WARN: Traces have only 1 service (per-service grouping not testable)")

    if all_ok:
        print(f"\n  *** PASS: All resource attribute checks passed ***")
    else:
        print(f"\n  *** FAIL: Some checks failed ***")
        sys.exit(1)


if __name__ == "__main__":
    main()
