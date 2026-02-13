#!/bin/bash
# Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
# Author: Madhukar Beema, Distinguished Engineer
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEY_PATH="${SSH_KEY:-$HOME/.ssh/mbaws-20262.pem}"

# Get EC2 IP
cd "$SCRIPT_DIR/terraform"
EC2_IP=$(terraform output -raw public_ip 2>/dev/null)
if [ -z "$EC2_IP" ]; then
    echo "ERROR: Could not get EC2 IP. Run 'terraform apply' first."
    exit 1
fi

SSH_CMD="ssh -o StrictHostKeyChecking=no -i $KEY_PATH ec2-user@$EC2_IP"

echo "=== Verifying Olly deployment on $EC2_IP ==="

$SSH_CMD <<'VERIFY'
echo ""
echo "=== Process Status ==="
echo "OTEL Collector: $(systemctl is-active otelcol-contrib 2>/dev/null || echo 'NOT FOUND')"
echo "Olly Agent PID: $(pgrep -x olly || echo 'NOT RUNNING')"
echo "Demo App PID:   $(pgrep -f 'python3.*app.py' || echo 'NOT RUNNING')"

echo ""
echo "=== On-Demand Tracing Status ==="
if [ -f /var/run/olly/control ]; then
    BYTE=$(od -An -tx1 -N1 /var/run/olly/control 2>/dev/null | tr -d ' ')
    if [ "$BYTE" = "01" ]; then
        echo "Tracing: ACTIVE"
    else
        echo "Tracing: DORMANT (run: sudo /opt/olly/olly trace start)"
    fi
else
    echo "Control file not found (always-active mode)"
fi

echo ""
echo "=== OTEL Collector Export Metrics ==="
if curl -s http://localhost:8888/metrics > /tmp/otel_metrics.txt 2>/dev/null; then
    echo "--- Sent ---"
    grep 'otelcol_exporter_sent_' /tmp/otel_metrics.txt | grep -v '^#' | grep 'grafana_cloud' || echo "  (no grafana_cloud exports)"
    grep 'otelcol_exporter_sent_' /tmp/otel_metrics.txt | grep -v '^#' | grep 'file/' || echo "  (no file exports)"
    echo "--- Failed ---"
    grep 'otelcol_exporter_send_failed' /tmp/otel_metrics.txt | grep -v '^#' | grep 'grafana_cloud' || echo "  (no failures)"
else
    echo "Collector metrics endpoint not available"
fi

echo ""
echo "=== Traces ==="
if [ -f /var/log/otel/traces.json ]; then
    echo "File size: $(wc -c < /var/log/otel/traces.json) bytes"
    TOTAL=$(grep -c '"traceId"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    SERVER=$(grep -c '"SPAN_KIND_SERVER"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    CLIENT=$(grep -c '"SPAN_KIND_CLIENT"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    CORRELATED=$(grep -c '"parentSpanId"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    echo "Total spans: $TOTAL (SERVER: $SERVER, CLIENT: $CLIENT, correlated: $CORRELATED)"

    # Cross-service trace stitching validation
    STITCHED=$(grep -c '"olly.stitched"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    echo "Cross-service stitched spans: $STITCHED"

    # Check for traceparent propagation (spans with both traceId and parentSpanId)
    if [ "$CLIENT" -gt 0 ] && [ "$SERVER" -gt 0 ]; then
        echo "Cross-service flow: Flask(CLIENT) → order-service(SERVER) detected"
    fi

    # MCP span detection
    MCP_SPANS=$(grep -c '"mcp.method.name"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    echo "MCP spans: $MCP_SPANS"
    if [ "$MCP_SPANS" -gt 0 ]; then
        echo "--- MCP methods detected ---"
        grep -o '"mcp.method.name","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | sort | uniq -c | sort -rn || true
        echo "--- MCP tool names ---"
        grep -o '"gen_ai.tool.name","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | sort -u || true
        echo "--- MCP session IDs (first 3) ---"
        grep -o '"mcp.session.id","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | head -3 || true
        echo "--- MCP transports ---"
        grep -o '"mcp.transport","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | sort -u || true
        echo "--- MCP server info ---"
        grep -o '"mcp.server.name","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | sort -u || true
        echo "--- MCP protocol version ---"
        grep -o '"mcp.protocol.version","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | sort -u || true
        echo "--- MCP tools count ---"
        grep -o '"mcp.tools.count","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | sort -u || true
        echo "--- MCP errors ---"
        grep -o '"rpc.jsonrpc.error_code","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null || echo "  (no MCP errors)"
    fi

    # GenAI span detection
    GENAI_SPANS=$(grep -c '"gen_ai.provider.name"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    echo "GenAI spans: $GENAI_SPANS"
    if [ "$GENAI_SPANS" -gt 0 ]; then
        echo "--- GenAI providers detected ---"
        grep -o '"gen_ai.provider.name","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | sort -u || true
        echo "--- GenAI models ---"
        grep -o '"gen_ai.response.model","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | sort -u || true
        echo "--- GenAI token usage (first 3) ---"
        grep -o '"gen_ai.usage.input_tokens","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | head -3 || true
        grep -o '"gen_ai.usage.output_tokens","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | head -3 || true
    fi

    echo "--- Last 5 span names ---"
    grep -o '"name":"[^"]*"' /var/log/otel/traces.json 2>/dev/null | tail -5

    echo "--- Service names in traces ---"
    grep -o '"service.name","value":{"stringValue":"[^"]*"}' /var/log/otel/traces.json 2>/dev/null | sort -u || true
else
    echo "NOT FOUND (file exporter not enabled or no data yet)"
fi

echo ""
echo "=== Logs ==="
if [ -f /var/log/otel/logs.json ]; then
    echo "File size: $(wc -c < /var/log/otel/logs.json) bytes"
    TOTAL_LOGS=$(grep -c '"body"' /var/log/otel/logs.json 2>/dev/null || echo 0)
    HOOK_LOGS=$(grep -c '"source","value":{"stringValue":"hook"}' /var/log/otel/logs.json 2>/dev/null || echo 0)
    FILE_LOGS=$(grep -c '"source","value":{"stringValue":"file"}' /var/log/otel/logs.json 2>/dev/null || echo 0)
    WITH_TRACE=$(grep -c '"traceId":"[0-9a-f]\{16,\}"' /var/log/otel/logs.json 2>/dev/null || echo 0)
    echo "Total logs: $TOTAL_LOGS (hook: $HOOK_LOGS, file: $FILE_LOGS)"
    echo "Logs with traceId: $WITH_TRACE"
    if [ "$HOOK_LOGS" -gt 0 ]; then
        PCT=$((WITH_TRACE * 100 / HOOK_LOGS))
        echo "Hook-log correlation rate: ${PCT}%"
    fi
else
    echo "NOT FOUND (file exporter not enabled or no data yet)"
fi

echo ""
echo "=== Metrics ==="
if [ -f /var/log/otel/metrics.json ]; then
    echo "File size: $(wc -c < /var/log/otel/metrics.json) bytes"
    echo "--- Metric names ---"
    grep -o '"name":"[^"]*"' /var/log/otel/metrics.json 2>/dev/null | sort -u | head -30
    echo "--- GenAI metrics ---"
    grep -c '"gen_ai.client.token.usage"' /var/log/otel/metrics.json 2>/dev/null && echo "  gen_ai.client.token.usage: FOUND" || echo "  gen_ai.client.token.usage: not yet"
    grep -c '"gen_ai.client.operation.duration"' /var/log/otel/metrics.json 2>/dev/null && echo "  gen_ai.client.operation.duration: FOUND" || echo "  gen_ai.client.operation.duration: not yet"
    echo "--- MCP metrics ---"
    grep -c '"mcp.client.request.count"' /var/log/otel/metrics.json 2>/dev/null && echo "  mcp.client.request.count: FOUND" || echo "  mcp.client.request.count: not yet"
    grep -c '"mcp.client.operation.duration"' /var/log/otel/metrics.json 2>/dev/null && echo "  mcp.client.operation.duration: FOUND" || echo "  mcp.client.operation.duration: not yet"
    grep -c '"mcp.client.error.count"' /var/log/otel/metrics.json 2>/dev/null && echo "  mcp.client.error.count: FOUND" || echo "  mcp.client.error.count: not yet"
else
    echo "NOT FOUND (file exporter not enabled or no data yet)"
fi

echo ""
echo "=== Demo App Logs (last 5 lines) ==="
if [ -f /var/log/demo-app/stdout.log ]; then
    tail -5 /var/log/demo-app/stdout.log
elif [ -f /var/log/demo-app/app.log ]; then
    tail -5 /var/log/demo-app/app.log
else
    echo "NOT FOUND"
fi

echo ""
echo "=== Olly Agent Logs (last 10 lines) ==="
if [ -f /var/log/olly.log ]; then
    tail -10 /var/log/olly.log
else
    echo "NOT FOUND"
fi
VERIFY

echo ""
echo "=== Verification complete ==="
