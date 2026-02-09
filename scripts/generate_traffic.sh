#!/bin/bash
# Generate test traffic for olly agent
# Usage: ./scripts/generate_traffic.sh [iterations]

set -e

ITERATIONS=${1:-10}
DELAY=${2:-0.5}

echo "=== Olly Traffic Generator ==="
echo "Iterations: $ITERATIONS"
echo "Delay: ${DELAY}s"
echo ""

# Check if libolly.so exists
HOOK_LIB=""
for path in ./lib/libolly.so /usr/lib/libolly.so /usr/local/lib/libolly.so; do
    if [ -f "$path" ]; then
        HOOK_LIB="$path"
        break
    fi
done

if [ -z "$HOOK_LIB" ]; then
    echo "WARNING: libolly.so not found. Run 'make hook' first."
    echo "Running without hook injection (agent won't see traffic)"
    PRELOAD=""
else
    echo "Using hook library: $HOOK_LIB"
    if [ "$(uname)" = "Darwin" ]; then
        PRELOAD="DYLD_INSERT_LIBRARIES=$HOOK_LIB"
    else
        PRELOAD="LD_PRELOAD=$HOOK_LIB"
    fi
fi

echo ""

# HTTP traffic
echo "--- HTTP Traffic ---"
for i in $(seq 1 $ITERATIONS); do
    echo "[$i/$ITERATIONS] GET http://httpbin.org/get"
    env $PRELOAD curl -s -o /dev/null -w "  Status: %{http_code}, Time: %{time_total}s\n" \
        http://httpbin.org/get 2>/dev/null || true
    sleep $DELAY
done

echo ""
echo "--- HTTPS Traffic (TLS interception) ---"
for i in $(seq 1 $ITERATIONS); do
    echo "[$i/$ITERATIONS] GET https://httpbin.org/get"
    env $PRELOAD curl -s -o /dev/null -w "  Status: %{http_code}, Time: %{time_total}s\n" \
        https://httpbin.org/get 2>/dev/null || true
    sleep $DELAY
done

echo ""
echo "--- HTTP POST Traffic ---"
for i in $(seq 1 $ITERATIONS); do
    echo "[$i/$ITERATIONS] POST https://httpbin.org/post"
    env $PRELOAD curl -s -o /dev/null -w "  Status: %{http_code}, Time: %{time_total}s\n" \
        -X POST -H "Content-Type: application/json" \
        -d '{"key":"value","iteration":'$i'}' \
        https://httpbin.org/post 2>/dev/null || true
    sleep $DELAY
done

# DNS traffic
echo ""
echo "--- DNS Traffic ---"
for i in $(seq 1 $ITERATIONS); do
    echo "[$i/$ITERATIONS] DNS lookup: example.com"
    env $PRELOAD nslookup example.com >/dev/null 2>&1 || true
    sleep $DELAY
done

echo ""
echo "=== Traffic generation complete ==="
echo "Check olly agent stdout or OTLP collector for captured traces."
