#!/usr/bin/env python3
"""Analyze OTEL traces for cross-service linking correctness.

Reads /var/log/otel/traces.json and checks for:
  1. Cross-trace parent references (parent in a different trace)
  2. Missing parents (parentSpanId not found in any span)
  3. Circular parent links
  4. Overall cross-service trace linking quality
"""

import json
import sys
from collections import defaultdict


def load_spans(path="/var/log/otel/traces.json"):
    """Parse OTEL JSON export into flat list of spans."""
    spans = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                batch = json.loads(line)
            except json.JSONDecodeError:
                continue
            for rs in batch.get("resourceSpans", []):
                svc = ""
                for attr in rs.get("resource", {}).get("attributes", []):
                    if attr.get("key") == "service.name":
                        svc = attr.get("value", {}).get("stringValue", "")
                for ss in rs.get("scopeSpans", []):
                    for span in ss.get("spans", []):
                        spans.append({
                            "traceId": span.get("traceId", ""),
                            "spanId": span.get("spanId", ""),
                            "parentSpanId": span.get("parentSpanId", ""),
                            "name": span.get("name", ""),
                            "kind": span.get("kind", 0),
                            "service": svc,
                            "startTimeUnixNano": span.get("startTimeUnixNano", ""),
                        })
    return spans


def analyze(spans):
    """Analyze spans for cross-service linking issues."""
    # Build indexes
    span_by_id = {}  # spanId → span
    spans_by_trace = defaultdict(list)
    for s in spans:
        span_by_id[s["spanId"]] = s
        spans_by_trace[s["traceId"]].append(s)

    cross_trace_parents = []
    missing_parents = []
    circular_links = []

    total_with_parent = 0
    cross_service_calls = 0  # CLIENT spans that should link to a SERVER

    for s in spans:
        pid = s["parentSpanId"]
        if not pid:
            continue
        total_with_parent += 1

        # Check if parent exists in any span
        parent = span_by_id.get(pid)
        if parent is None:
            missing_parents.append({
                "spanId": s["spanId"],
                "parentSpanId": pid,
                "name": s["name"],
                "service": s["service"],
                "traceId": s["traceId"],
            })
            continue

        # Check if parent is in a different trace (cross-trace reference)
        if parent["traceId"] != s["traceId"]:
            cross_trace_parents.append({
                "spanId": s["spanId"],
                "parentSpanId": pid,
                "spanTrace": s["traceId"],
                "parentTrace": parent["traceId"],
                "name": s["name"],
                "service": s["service"],
            })

    # Check for circular links
    for s in spans:
        visited = set()
        current = s["spanId"]
        while current:
            if current in visited:
                circular_links.append({
                    "startSpan": s["spanId"],
                    "cycle_at": current,
                    "name": s["name"],
                })
                break
            visited.add(current)
            parent_span = span_by_id.get(current)
            if parent_span:
                current = parent_span.get("parentSpanId", "")
            else:
                break

    # Count cross-service calls (CLIENT spans with kind=3 or SERVER kind=2)
    kind_map = {1: "INTERNAL", 2: "SERVER", 3: "CLIENT", 4: "PRODUCER", 5: "CONSUMER"}
    client_spans = [s for s in spans if s["kind"] in (3, "SPAN_KIND_CLIENT")]
    server_spans = [s for s in spans if s["kind"] in (2, "SPAN_KIND_SERVER")]

    # Count cross-service pairs (CLIENT in service A → SERVER in service B)
    services = set(s["service"] for s in spans if s["service"])

    return {
        "total_spans": len(spans),
        "total_traces": len(spans_by_trace),
        "spans_with_parent": total_with_parent,
        "services": sorted(services),
        "client_spans": len(client_spans),
        "server_spans": len(server_spans),
        "cross_trace_parents": cross_trace_parents,
        "missing_parents": missing_parents,
        "circular_links": circular_links,
    }


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/otel/traces.json"
    print(f"Loading traces from {path}...")
    spans = load_spans(path)
    if not spans:
        print("ERROR: No spans found!")
        sys.exit(1)

    result = analyze(spans)

    print(f"\n{'='*60}")
    print(f"TRACE ANALYSIS REPORT")
    print(f"{'='*60}")
    print(f"Total spans:          {result['total_spans']}")
    print(f"Total traces:         {result['total_traces']}")
    print(f"Spans with parent:    {result['spans_with_parent']}")
    print(f"Services:             {', '.join(result['services']) or 'none'}")
    print(f"CLIENT spans:         {result['client_spans']}")
    print(f"SERVER spans:         {result['server_spans']}")

    print(f"\n--- CROSS-TRACE PARENT REFERENCES ---")
    ct = result["cross_trace_parents"]
    print(f"Count: {len(ct)}")
    for item in ct[:10]:
        print(f"  span={item['spanId'][:8]}.. parent={item['parentSpanId'][:8]}.. "
              f"spanTrace={item['spanTrace'][:8]}.. parentTrace={item['parentTrace'][:8]}.. "
              f"name={item['name']} svc={item['service']}")
    if len(ct) > 10:
        print(f"  ... and {len(ct)-10} more")

    print(f"\n--- MISSING PARENTS ---")
    mp = result["missing_parents"]
    print(f"Count: {len(mp)}")
    for item in mp[:10]:
        print(f"  span={item['spanId'][:8]}.. parent={item['parentSpanId'][:8]}.. "
              f"name={item['name']} svc={item['service']} trace={item['traceId'][:8]}..")
    if len(mp) > 10:
        print(f"  ... and {len(mp)-10} more")

    print(f"\n--- CIRCULAR LINKS ---")
    cl = result["circular_links"]
    print(f"Count: {len(cl)}")
    for item in cl[:10]:
        print(f"  start={item['startSpan'][:8]}.. cycle_at={item['cycle_at'][:8]}.. name={item['name']}")

    # Compute error rate
    total_cross = result["spans_with_parent"]
    errors = len(ct) + len(mp)
    if total_cross > 0:
        error_rate = errors * 100.0 / total_cross
    else:
        error_rate = 0.0

    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"Cross-trace parent refs:  {len(ct)}")
    print(f"Missing parents:          {len(mp)}")
    print(f"Circular links:           {len(cl)}")
    print(f"Error rate:               {error_rate:.1f}% ({errors}/{total_cross} parent refs)")

    if errors == 0 and len(cl) == 0:
        print(f"\n*** ALL CLEAR — No trace linking issues detected! ***")
        sys.exit(0)
    else:
        print(f"\n*** ISSUES DETECTED — {errors} errors in trace linking ***")
        sys.exit(1)


if __name__ == "__main__":
    main()
