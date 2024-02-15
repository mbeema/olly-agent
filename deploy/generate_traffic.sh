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

BASE_URL="http://$EC2_IP:5000"
ITERATIONS="${1:-30}"

echo "=== Generating traffic against $BASE_URL ($ITERATIONS iterations) ==="

for i in $(seq 1 "$ITERATIONS"); do
    echo "--- Iteration $i/$ITERATIONS ---"

    # Health check
    curl -s "$BASE_URL/" > /dev/null

    # List users
    curl -s "$BASE_URL/users" > /dev/null

    # Create user
    curl -s -X POST "$BASE_URL/users" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"User$i\",\"email\":\"user${i}@test.com\"}" > /dev/null

    # Get specific user
    curl -s "$BASE_URL/users/1" > /dev/null

    # Slow endpoint (short delay)
    curl -s "$BASE_URL/slow?delay=0.5" > /dev/null

    # Error endpoint
    curl -s "$BASE_URL/error" > /dev/null || true

    sleep 1
done

echo ""
echo "=== Traffic generation complete ==="
echo "Run 'deploy/verify.sh' to check OTEL output."
