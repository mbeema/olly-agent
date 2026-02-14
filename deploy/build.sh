#!/bin/bash
# Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
# Author: Madhukar Beema, Distinguished Engineer
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

# Cross-compile Go MCP demo server
echo "Building mcp-server..."
cd "$PROJECT_DIR/deploy/demo-app/mcp-server"
GOOS=linux GOARCH=amd64 go build -o "$BUILD_DIR/mcp-server" .
echo "Binary: $BUILD_DIR/mcp-server"

# Compile Java catalog-service (portable bytecode — runs on any JDK 17+)
echo "Building catalog-service (Java)..."
if command -v javac &> /dev/null; then
    cd "$PROJECT_DIR/deploy/demo-app/catalog-service"
    javac --release 17 CatalogService.java
    echo "Compiled: CatalogService.class (target JDK 17)"
else
    echo "WARN: javac not found — Java will be compiled on EC2"
fi

# Build .NET pricing-service (self-contained linux-x64 binary)
echo "Building pricing-service (.NET)..."
if command -v dotnet &> /dev/null; then
    cd "$PROJECT_DIR/deploy/demo-app/pricing-service"
    dotnet publish -c Release -r linux-x64 --self-contained -o "$BUILD_DIR/pricing-service-publish" 2>/dev/null || {
        echo "WARN: dotnet publish failed — will build on EC2"
    }
else
    echo "WARN: dotnet not found — .NET will be built on EC2"
fi

# Node.js stock-service: source-only, npm install on EC2
echo "stock-service (Node.js): source-only, deps installed on EC2"

# Package tarball
cd "$BUILD_DIR"
mkdir -p olly-deploy/configs
cp olly olly-deploy/
cp order-service olly-deploy/
cp mcp-server olly-deploy/
cp "$SCRIPT_DIR/configs/"*.yaml olly-deploy/configs/
cp "$SCRIPT_DIR/otel-collector.yaml" olly-deploy/
cp -r "$SCRIPT_DIR/demo-app/." olly-deploy/demo-app/
# Include .NET self-contained publish output if available
if [ -d "$BUILD_DIR/pricing-service-publish" ]; then
    mkdir -p olly-deploy/pricing-service-publish
    cp -r "$BUILD_DIR/pricing-service-publish/." olly-deploy/pricing-service-publish/
fi
tar czf olly-deploy.tar.gz olly-deploy/
rm -rf olly-deploy

echo "Package: $BUILD_DIR/olly-deploy.tar.gz"
echo "=== Build complete ==="
