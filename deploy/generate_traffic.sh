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

BASE_URL="http://$EC2_IP:5000"
ITERATIONS="${1:-30}"

echo "=== Generating traffic against $BASE_URL ($ITERATIONS iterations) ==="

for i in $(seq 1 "$ITERATIONS"); do
    echo "--- Iteration $i/$ITERATIONS ---"

    # Health check
    curl -s "$BASE_URL/" > /dev/null

    # List users (Flask → PostgreSQL)
    curl -s "$BASE_URL/users" > /dev/null

    # Create user (Flask → PostgreSQL)
    curl -s -X POST "$BASE_URL/users" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"User$i\",\"email\":\"user${i}@test.com\"}" > /dev/null

    # Get specific user
    curl -s "$BASE_URL/users/1" > /dev/null

    # Cross-service: List orders (Flask → order-service → PostgreSQL)
    curl -s "$BASE_URL/orders" > /dev/null || true

    # Cross-service: Create order (Flask → order-service → PostgreSQL)
    curl -s -X POST "$BASE_URL/orders" \
        -H "Content-Type: application/json" \
        -d "{\"user_id\":1,\"product\":\"Widget-$i\",\"amount\":$((i * 10))}" > /dev/null || true

    # Cross-service with explicit traceparent (upstream-propagated)
    TRACE_ID=$(openssl rand -hex 16 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(16))')
    SPAN_ID=$(openssl rand -hex 8 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(8))')
    curl -s "$BASE_URL/orders" \
        -H "traceparent: 00-${TRACE_ID}-${SPAN_ID}-01" > /dev/null || true

    # Slow endpoint (short delay)
    curl -s "$BASE_URL/slow?delay=0.5" > /dev/null

    # Error endpoint
    curl -s "$BASE_URL/error" > /dev/null || true

    sleep 1
done

echo ""
echo "=== Traffic generation complete ==="
echo "Run 'deploy/verify.sh' to check OTEL output."
