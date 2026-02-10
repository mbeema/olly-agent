#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/dist"

echo "=== Building Olly for Linux amd64 ==="

mkdir -p "$BUILD_DIR"

# Cross-compile Go binary
cd "$PROJECT_DIR"
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)

GOOS=linux GOARCH=amd64 go build \
    -ldflags "-X main.version=$VERSION -X main.commit=$COMMIT -X main.buildDate=$BUILD_DATE" \
    -o "$BUILD_DIR/olly" \
    ./cmd/olly

echo "Binary: $BUILD_DIR/olly"

# Cross-compile Go order-service
echo "Building order-service..."
cd "$PROJECT_DIR/deploy/demo-app/order-service"
GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/order-service" .
echo "Binary: $BUILD_DIR/order-service"

# Package tarball
cd "$BUILD_DIR"
mkdir -p olly-deploy/configs
cp olly olly-deploy/
cp order-service olly-deploy/
cp "$SCRIPT_DIR/configs/"*.yaml olly-deploy/configs/
cp "$SCRIPT_DIR/otel-collector.yaml" olly-deploy/
cp -r "$SCRIPT_DIR/demo-app" olly-deploy/
cp "$PROJECT_DIR/pkg/hook/c/libolly.c" olly-deploy/

tar czf olly-deploy.tar.gz olly-deploy/
rm -rf olly-deploy

echo "Package: $BUILD_DIR/olly-deploy.tar.gz"
echo "=== Build complete ==="
