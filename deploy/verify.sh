#!/bin/bash
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

echo "=== Verifying OTEL Collector output on $EC2_IP ==="

$SSH_CMD <<'VERIFY'
echo ""
echo "=== Process Status ==="
echo "OTEL Collector: $(systemctl is-active otelcol-contrib)"
echo "Olly Agent PID: $(pgrep -x olly || echo 'NOT RUNNING')"
echo "Demo App PID:   $(pgrep -x python3 || echo 'NOT RUNNING')"

echo ""
echo "=== Traces ==="
if [ -f /var/log/otel/traces.json ]; then
    echo "File size: $(wc -c < /var/log/otel/traces.json) bytes"
    TOTAL=$(grep -c '"traceId"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    SERVER=$(grep -c '"SPAN_KIND_SERVER"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    CLIENT=$(grep -c '"SPAN_KIND_CLIENT"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    CORRELATED=$(grep -c '"parentSpanId"' /var/log/otel/traces.json 2>/dev/null || echo 0)
    echo "Total spans: $TOTAL (SERVER: $SERVER, CLIENT: $CLIENT, correlated: $CORRELATED)"
    echo "--- Last 3 span names ---"
    grep -o '"name":"[^"]*"' /var/log/otel/traces.json 2>/dev/null | tail -3
else
    echo "NOT FOUND"
fi

echo ""
echo "=== Metrics ==="
if [ -f /var/log/otel/metrics.json ]; then
    echo "File size: $(wc -c < /var/log/otel/metrics.json) bytes"
    echo "--- Metric names ---"
    grep -o '"name":"[^"]*"' /var/log/otel/metrics.json 2>/dev/null | sort -u | head -20
else
    echo "NOT FOUND"
fi

echo ""
echo "=== Logs ==="
if [ -f /var/log/otel/logs.json ]; then
    echo "File size: $(wc -c < /var/log/otel/logs.json) bytes"
    echo "--- Last 3 log entries ---"
    tail -3 /var/log/otel/logs.json | python3 -m json.tool 2>/dev/null || tail -3 /var/log/otel/logs.json
else
    echo "NOT FOUND"
fi

echo ""
echo "=== Demo App Logs (last 5 lines) ==="
if [ -f /var/log/demo-app/app.log ]; then
    tail -5 /var/log/demo-app/app.log
elif [ -f /var/log/demo-app/stdout.log ]; then
    tail -5 /var/log/demo-app/stdout.log
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
