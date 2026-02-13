#!/usr/bin/env python3
"""Analyze OTEL traces for cross-service linking correctness.

Reads /var/log/otel/traces.json (OTLP JSON format) and analyzes:
  1. Total spans, SERVER vs CLIENT, by service name
  2. MCP spans (those with mcp.method attribute)
  3. Stitched spans (olly.stitched=true)
  4. MCP CLIENT->SERVER pair linking quality
  5. HTTP cross-service pairs (app -> order-service)
  6. Orphaned parent references
  7. Overall trace linking error rate
"""

import json
import sys
from collections import defaultdict


def get_attr(span_attrs, key):
    """Extract attribute value from OTLP attributes array."""
    for attr in (span_attrs or []):
        if attr.get("key") == key:
            val = attr.get("value", {})
            # Try all OTLP value types
            for vtype in ("stringValue", "intValue", "boolValue", "doubleValue"):
                if vtype in val:
                    return val[vtype]
    return None


def load_spans(path="/var/log/otel/traces.json"):
    """Parse OTEL JSON export into flat list of spans with extracted attributes."""
    spans = []
    line_count = 0
    parse_errors = 0

    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            line_count += 1
            try:
                batch = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue

            for rs in batch.get("resourceSpans", []):
                # Extract service name from resource attributes
                svc = ""
                res_attrs = rs.get("resource", {}).get("attributes", [])
                svc = get_attr(res_attrs, "service.name") or ""

                for ss in rs.get("scopeSpans", []):
                    for span in ss.get("spans", []):
                        span_attrs = span.get("attributes", [])

                        # Extract key attributes we need for analysis
                        parsed = {
                            "traceId": span.get("traceId", ""),
                            "spanId": span.get("spanId", ""),
                            "parentSpanId": span.get("parentSpanId", ""),
                            "name": span.get("name", ""),
                            "kind": span.get("kind", 0),
                            "service": svc,
                            "startTimeUnixNano": span.get("startTimeUnixNano", ""),
                            "endTimeUnixNano": span.get("endTimeUnixNano", ""),
                            # Olly-specific attributes
                            "olly.stitched": get_attr(span_attrs, "olly.stitched"),
                            "olly.trace_source": get_attr(span_attrs, "olly.trace_source"),
                            "olly.stitched.client_service": get_attr(span_attrs, "olly.stitched.client_service"),
                            # MCP attributes (OTEL semantic conventions Jan 2026)
                            "mcp.method": get_attr(span_attrs, "mcp.method.name"),
                            "mcp.tool.name": get_attr(span_attrs, "gen_ai.tool.name"),
                            "mcp.request.id": get_attr(span_attrs, "jsonrpc.request.id"),
                            "mcp.resource.uri": get_attr(span_attrs, "mcp.resource.uri"),
                            "mcp.prompt.name": get_attr(span_attrs, "gen_ai.prompt.name"),
                            "mcp.session.id": get_attr(span_attrs, "mcp.session.id"),
                            "mcp.transport": get_attr(span_attrs, "mcp.transport"),
                            "mcp.error.code": get_attr(span_attrs, "rpc.jsonrpc.error_code"),
                            "mcp.error.message": get_attr(span_attrs, "rpc.jsonrpc.error_message"),
                            # HTTP attributes
                            "http.request.method": get_attr(span_attrs, "http.request.method"),
                            "url.path": get_attr(span_attrs, "url.path"),
                            "http.response.status_code": get_attr(span_attrs, "http.response.status_code"),
                            "server.address": get_attr(span_attrs, "server.address"),
                            # Protocol
                            "network.protocol": get_attr(span_attrs, "network.protocol.name"),
                            # GenAI
                            "gen_ai.system": get_attr(span_attrs, "gen_ai.provider.name"),
                            "gen_ai.operation.name": get_attr(span_attrs, "gen_ai.operation.name"),
                            # DB
                            "db.system": get_attr(span_attrs, "db.system"),
                        }
                        spans.append(parsed)

    print("Lines read: %d, parse errors: %d" % (line_count, parse_errors))
    return spans


def analyze(spans):
    """Run full analysis on parsed spans."""

    # ================================================================
    # 1. Basic counts
    # ================================================================
    total = len(spans)
    kind_names = {1: "INTERNAL", 2: "SERVER", 3: "CLIENT", 4: "PRODUCER", 5: "CONSUMER"}

    # Count by kind
    by_kind = defaultdict(int)
    for s in spans:
        by_kind[s["kind"]] += 1

    # Count by service
    by_service = defaultdict(lambda: {"total": 0, "SERVER": 0, "CLIENT": 0, "other": 0})
    for s in spans:
        svc = s["service"] or "(unknown)"
        by_service[svc]["total"] += 1
        if s["kind"] == 2:
            by_service[svc]["SERVER"] += 1
        elif s["kind"] == 3:
            by_service[svc]["CLIENT"] += 1
        else:
            by_service[svc]["other"] += 1

    # ================================================================
    # 2. Build indexes
    # ================================================================
    span_by_id = {}         # spanId -> span
    spans_by_trace = defaultdict(list)  # traceId -> [spans]

    for s in spans:
        span_by_id[s["spanId"]] = s
        spans_by_trace[s["traceId"]].append(s)

    total_traces = len(spans_by_trace)

    # ================================================================
    # 3. MCP spans
    # ================================================================
    mcp_spans = [s for s in spans if s["mcp.method"]]
    mcp_client = [s for s in mcp_spans if s["kind"] == 3]
    mcp_server = [s for s in mcp_spans if s["kind"] == 2]

    # MCP methods breakdown
    mcp_methods = defaultdict(int)
    for s in mcp_spans:
        mcp_methods[s["mcp.method"]] += 1

    # MCP CLIENT spans with stitching
    mcp_client_stitched = [s for s in mcp_client if s["olly.stitched"] == "true"]

    # MCP SERVER spans with parentSpanId
    mcp_server_with_parent = [s for s in mcp_server if s["parentSpanId"]]

    # MCP CLIENT->SERVER pairs: CLIENT.traceId == SERVER.traceId AND SERVER.parentSpanId == CLIENT.spanId
    mcp_client_by_span = {}
    for s in mcp_client:
        mcp_client_by_span[s["spanId"]] = s

    mcp_pairs = []
    for s in mcp_server:
        if s["parentSpanId"] and s["parentSpanId"] in mcp_client_by_span:
            client = mcp_client_by_span[s["parentSpanId"]]
            if client["traceId"] == s["traceId"]:
                mcp_pairs.append((client, s))

    # ================================================================
    # 4. Stitched spans
    # ================================================================
    stitched_spans = [s for s in spans if s["olly.stitched"] == "true"]

    # ================================================================
    # 5. HTTP cross-service pairs (app -> order-service)
    # ================================================================
    # CLIENT spans from "app" service
    app_clients = [s for s in spans if s["kind"] == 3 and s["service"] == "app"]
    # SERVER spans from "order-service"
    order_servers = [s for s in spans if s["kind"] == 2 and s["service"] == "order-service"]

    order_server_by_parent = defaultdict(list)
    for s in order_servers:
        if s["parentSpanId"]:
            order_server_by_parent[s["parentSpanId"]].append(s)

    http_cross_pairs = []
    for c in app_clients:
        matches = order_server_by_parent.get(c["spanId"], [])
        for srv in matches:
            if srv["traceId"] == c["traceId"]:
                http_cross_pairs.append((c, srv))

    # Also count any CLIENT->SERVER pair across services (regardless of service names)
    all_server_by_parent = defaultdict(list)
    for s in spans:
        if s["kind"] == 2 and s["parentSpanId"]:
            all_server_by_parent[s["parentSpanId"]].append(s)

    all_cross_service_pairs = []
    for c in spans:
        if c["kind"] != 3:
            continue
        matches = all_server_by_parent.get(c["spanId"], [])
        for srv in matches:
            if srv["traceId"] == c["traceId"] and srv["service"] != c["service"]:
                all_cross_service_pairs.append((c, srv))

    # ================================================================
    # 6. Orphaned parent references
    # ================================================================
    orphaned_parents = []
    upstream_parents = []  # Expected: from external callers (e.g., curl traceparent)
    cross_trace_parents = []
    total_with_parent = 0

    for s in spans:
        pid = s["parentSpanId"]
        if not pid:
            continue
        total_with_parent += 1

        parent = span_by_id.get(pid)
        if parent is None:
            # SERVER spans with trace_source=traceparent have parentSpanId from
            # an upstream service's traceparent header. The parent span is from
            # an external service not monitored by this agent (e.g., curl).
            # This is expected, not an error.
            if s["kind"] == 2 and s["olly.trace_source"] == "traceparent":
                upstream_parents.append(s)
            else:
                orphaned_parents.append(s)
        elif parent["traceId"] != s["traceId"]:
            cross_trace_parents.append(s)

    # ================================================================
    # 7. Multi-service traces
    # ================================================================
    multi_service_traces = 0
    for tid, trace_spans in spans_by_trace.items():
        services_in_trace = set(s["service"] for s in trace_spans if s["service"])
        if len(services_in_trace) > 1:
            multi_service_traces += 1

    # ================================================================
    # 8. Trace source breakdown
    # ================================================================
    trace_source_counts = defaultdict(int)
    for s in spans:
        src = s["olly.trace_source"]
        if src:
            trace_source_counts[src] += 1

    # ================================================================
    # 9. Protocol breakdown
    # ================================================================
    db_systems = defaultdict(int)
    for s in spans:
        db = s["db.system"]
        if db:
            db_systems[db] += 1

    genai_spans = [s for s in spans if s["gen_ai.system"]]

    return {
        "total": total,
        "total_traces": total_traces,
        "by_kind": dict(by_kind),
        "by_service": dict(by_service),
        "kind_names": kind_names,
        "mcp_spans": mcp_spans,
        "mcp_client": mcp_client,
        "mcp_server": mcp_server,
        "mcp_methods": dict(mcp_methods),
        "mcp_client_stitched": mcp_client_stitched,
        "mcp_server_with_parent": mcp_server_with_parent,
        "mcp_pairs": mcp_pairs,
        "stitched_spans": stitched_spans,
        "http_cross_pairs": http_cross_pairs,
        "all_cross_service_pairs": all_cross_service_pairs,
        "orphaned_parents": orphaned_parents,
        "upstream_parents": upstream_parents,
        "cross_trace_parents": cross_trace_parents,
        "total_with_parent": total_with_parent,
        "multi_service_traces": multi_service_traces,
        "trace_source_counts": dict(trace_source_counts),
        "db_systems": dict(db_systems),
        "genai_spans": genai_spans,
        "app_clients": app_clients,
        "order_servers": order_servers,
    }


def print_report(r):
    """Print a comprehensive analysis report."""
    sep = "=" * 70
    sub = "-" * 70

    print("")
    print(sep)
    print("  TRACE LINKING QUALITY ANALYSIS REPORT")
    print(sep)

    # --- Section 1: Overview ---
    print("")
    print("1. OVERVIEW")
    print(sub)
    print("  Total spans:           %d" % r["total"])
    print("  Total traces:          %d" % r["total_traces"])
    print("  Multi-service traces:  %d" % r["multi_service_traces"])
    print("  Spans with parent:     %d" % r["total_with_parent"])

    print("")
    print("  By span kind:")
    for kind_num in sorted(r["by_kind"].keys()):
        label = r["kind_names"].get(kind_num, "KIND_%d" % kind_num)
        print("    %-12s  %d" % (label, r["by_kind"][kind_num]))

    # --- Section 2: By Service ---
    print("")
    print("2. SPANS BY SERVICE")
    print(sub)
    print("  %-25s %7s %7s %7s %7s" % ("Service", "Total", "SERVER", "CLIENT", "Other"))
    print("  %-25s %7s %7s %7s %7s" % ("-" * 25, "-" * 7, "-" * 7, "-" * 7, "-" * 7))
    for svc in sorted(r["by_service"].keys()):
        info = r["by_service"][svc]
        print("  %-25s %7d %7d %7d %7d" % (svc, info["total"], info["SERVER"], info["CLIENT"], info["other"]))

    # --- Section 3: MCP Spans ---
    print("")
    print("3. MCP SPANS (mcp.method attribute present)")
    print(sub)
    print("  Total MCP spans:              %d" % len(r["mcp_spans"]))
    print("  MCP CLIENT spans:             %d" % len(r["mcp_client"]))
    print("  MCP SERVER spans:             %d" % len(r["mcp_server"]))

    if r["mcp_methods"]:
        print("")
        print("  MCP methods breakdown:")
        for method, count in sorted(r["mcp_methods"].items(), key=lambda x: -x[1]):
            print("    %-40s %d" % (method, count))

    # MCP tool names
    tool_names = set()
    for s in r["mcp_spans"]:
        tn = s["mcp.tool.name"]
        if tn:
            tool_names.add(tn)
    if tool_names:
        print("")
        print("  MCP tool names: %s" % ", ".join(sorted(tool_names)))

    # --- Section 4: Stitching ---
    print("")
    print("4. TRACE STITCHING")
    print(sub)
    print("  Total stitched spans:         %d" % len(r["stitched_spans"]))

    # Stitched by service
    stitched_by_svc = defaultdict(int)
    for s in r["stitched_spans"]:
        stitched_by_svc[s["service"] or "(unknown)"] += 1
    if stitched_by_svc:
        print("  Stitched by service:")
        for svc, cnt in sorted(stitched_by_svc.items()):
            print("    %-25s %d" % (svc, cnt))

    # Trace source breakdown
    if r["trace_source_counts"]:
        print("")
        print("  Trace source breakdown (olly.trace_source):")
        for src, cnt in sorted(r["trace_source_counts"].items()):
            print("    %-20s %d" % (src, cnt))

    # --- Section 5: MCP Linking ---
    print("")
    print("5. MCP TRACE LINKING QUALITY")
    print(sub)
    print("  MCP CLIENT spans with olly.stitched=true:  %d / %d" % (
        len(r["mcp_client_stitched"]), len(r["mcp_client"])))
    print("  MCP SERVER spans with parentSpanId:        %d / %d" % (
        len(r["mcp_server_with_parent"]), len(r["mcp_server"])))
    print("  MCP CLIENT->SERVER linked pairs:           %d" % len(r["mcp_pairs"]))

    if r["mcp_pairs"]:
        print("")
        print("  MCP linked pairs detail:")
        for client, server in r["mcp_pairs"][:20]:
            print("    CLIENT[%s] %s -> SERVER[%s] %s  method=%s trace=%s..%s" % (
                client["service"],
                client["spanId"][:8],
                server["service"],
                server["spanId"][:8],
                server.get("mcp.method", "?"),
                server["traceId"][:8],
                server["traceId"][-4:],
            ))
        if len(r["mcp_pairs"]) > 20:
            print("    ... and %d more" % (len(r["mcp_pairs"]) - 20))

    # Show unlinked MCP SERVER spans (no parent)
    mcp_server_no_parent = [s for s in r["mcp_server"] if not s["parentSpanId"]]
    if mcp_server_no_parent:
        print("")
        print("  MCP SERVER spans WITHOUT parent (%d):" % len(mcp_server_no_parent))
        for s in mcp_server_no_parent[:10]:
            print("    span=%s method=%s svc=%s trace=%s..%s" % (
                s["spanId"][:8],
                s["mcp.method"],
                s["service"],
                s["traceId"][:8],
                s["traceId"][-4:],
            ))
        if len(mcp_server_no_parent) > 10:
            print("    ... and %d more" % (len(mcp_server_no_parent) - 10))

    # --- Section 6: HTTP Cross-Service Pairs ---
    print("")
    print("6. HTTP CROSS-SERVICE PAIRS")
    print(sub)
    print("  app CLIENT spans:                 %d" % len(r["app_clients"]))
    print("  order-service SERVER spans:       %d" % len(r["order_servers"]))
    print("  app->order-service linked pairs:  %d" % len(r["http_cross_pairs"]))
    print("  All cross-service linked pairs:   %d" % len(r["all_cross_service_pairs"]))

    if r["all_cross_service_pairs"]:
        # Group by service pair
        pair_counts = defaultdict(int)
        for c, s in r["all_cross_service_pairs"]:
            pair_key = "%s -> %s" % (c["service"] or "?", s["service"] or "?")
            pair_counts[pair_key] += 1
        print("")
        print("  Cross-service pair breakdown:")
        for pair_key, cnt in sorted(pair_counts.items(), key=lambda x: -x[1]):
            print("    %-40s %d" % (pair_key, cnt))

    # --- Section 7: Orphaned Parents ---
    print("")
    print("7. ORPHANED PARENT REFERENCES")
    print(sub)
    print("  Missing parents (parentSpanId not found):     %d" % len(r["orphaned_parents"]))
    print("  Upstream parents (from external traceparent): %d (expected, not errors)" % len(r["upstream_parents"]))
    print("  Cross-trace parents (parent in diff trace):   %d" % len(r["cross_trace_parents"]))

    if r["orphaned_parents"]:
        print("")
        print("  Missing parent details (first 15):")
        for s in r["orphaned_parents"][:15]:
            print("    span=%s parent=%s name=%-30s svc=%-15s trace=%s..%s" % (
                s["spanId"][:8],
                s["parentSpanId"][:8],
                s["name"][:30],
                s["service"][:15],
                s["traceId"][:8],
                s["traceId"][-4:],
            ))
        if len(r["orphaned_parents"]) > 15:
            print("    ... and %d more" % (len(r["orphaned_parents"]) - 15))

    if r["cross_trace_parents"]:
        print("")
        print("  Cross-trace parent details (first 15):")
        for s in r["cross_trace_parents"][:15]:
            print("    span=%s parent=%s name=%-30s svc=%-15s trace=%s..%s" % (
                s["spanId"][:8],
                s["parentSpanId"][:8],
                s["name"][:30],
                s["service"][:15],
                s["traceId"][:8],
                s["traceId"][-4:],
            ))
        if len(r["cross_trace_parents"]) > 15:
            print("    ... and %d more" % (len(r["cross_trace_parents"]) - 15))

    # --- Section 8: Protocol/DB/GenAI breakdown ---
    if r["db_systems"] or r["genai_spans"]:
        print("")
        print("8. PROTOCOL BREAKDOWN")
        print(sub)
        if r["db_systems"]:
            print("  Database spans by system:")
            for db, cnt in sorted(r["db_systems"].items(), key=lambda x: -x[1]):
                print("    %-20s %d" % (db, cnt))
        if r["genai_spans"]:
            print("  GenAI spans: %d" % len(r["genai_spans"]))
            genai_ops = defaultdict(int)
            for s in r["genai_spans"]:
                op = s["gen_ai.operation.name"] or "unknown"
                provider = s["gen_ai.system"] or "unknown"
                genai_ops["%s/%s" % (provider, op)] += 1
            for key, cnt in sorted(genai_ops.items()):
                print("    %-30s %d" % (key, cnt))

    # --- SUMMARY ---
    errors = len(r["orphaned_parents"]) + len(r["cross_trace_parents"])
    total_parent_refs = r["total_with_parent"]
    if total_parent_refs > 0:
        error_rate = errors * 100.0 / total_parent_refs
    else:
        error_rate = 0.0

    print("")
    print(sep)
    print("  SUMMARY")
    print(sep)
    print("  Total spans:                %d" % r["total"])
    print("  Total traces:               %d" % r["total_traces"])
    print("  Multi-service traces:       %d" % r["multi_service_traces"])
    print("  Stitched spans:             %d" % len(r["stitched_spans"]))
    print("  MCP spans:                  %d" % len(r["mcp_spans"]))
    print("  MCP CLIENT->SERVER pairs:   %d" % len(r["mcp_pairs"]))
    print("  Cross-service pairs:        %d" % len(r["all_cross_service_pairs"]))
    print("  Missing parents:            %d" % len(r["orphaned_parents"]))
    print("  Upstream parents:           %d (expected)" % len(r["upstream_parents"]))
    print("  Cross-trace parents:        %d" % len(r["cross_trace_parents"]))
    print("  Error rate:                 %.1f%% (%d/%d parent refs)" % (
        error_rate, errors, total_parent_refs))
    print("")

    if errors == 0:
        print("  *** ALL CLEAR -- No trace linking issues detected! ***")
    else:
        print("  *** ISSUES DETECTED -- %d errors in trace linking ***" % errors)

    print("")
    return errors


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/otel/traces.json"
    print("Loading traces from %s..." % path)

    try:
        spans = load_spans(path)
    except FileNotFoundError:
        print("ERROR: File not found: %s" % path)
        sys.exit(1)
    except Exception as e:
        print("ERROR: Failed to load traces: %s" % str(e))
        sys.exit(1)

    if not spans:
        print("ERROR: No spans found!")
        sys.exit(1)

    r = analyze(spans)
    errors = print_report(r)
    sys.exit(0 if errors == 0 else 1)


if __name__ == "__main__":
    main()
