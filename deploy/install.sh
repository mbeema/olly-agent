#!/usr/bin/env bash
# Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
# Author: Madhukar Beema, Distinguished Engineer
set -euo pipefail

# Olly Agent Installer
# Usage: curl -sSL https://get.olly.dev | sudo bash

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/olly"
RUN_DIR="/var/run/olly"
LOG_DIR="/var/log/olly"
BINARY_NAME="olly"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# Check root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root (use sudo)"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64)  ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *)
        error "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
    error "Olly agent currently supports Linux only (detected: $OS)"
    exit 1
fi

info "Detected platform: ${OS}/${ARCH}"

# Create directories
info "Creating directories..."
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$RUN_DIR" "$LOG_DIR"

# Install binary
if [ -f "bin/${BINARY_NAME}-linux-${ARCH}" ]; then
    info "Installing from local build..."
    cp "bin/${BINARY_NAME}-linux-${ARCH}" "${INSTALL_DIR}/${BINARY_NAME}"
elif [ -f "bin/${BINARY_NAME}" ]; then
    cp "bin/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
else
    error "No binary found. Build first with: make build-linux"
    exit 1
fi
chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
info "Installed ${INSTALL_DIR}/${BINARY_NAME}"

# Install default configs if not present
if [ -d "deploy/configs" ]; then
    for f in deploy/configs/*.yaml; do
        basename=$(basename "$f")
        if [ ! -f "${CONFIG_DIR}/${basename}" ]; then
            cp "$f" "${CONFIG_DIR}/${basename}"
            info "Installed config: ${CONFIG_DIR}/${basename}"
        else
            warn "Config already exists, skipping: ${CONFIG_DIR}/${basename}"
        fi
    done
fi

# Install systemd service
if command -v systemctl &>/dev/null; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    SERVICE_FILE=""
    if [ -f "${SCRIPT_DIR}/olly.service" ]; then
        SERVICE_FILE="${SCRIPT_DIR}/olly.service"
    elif [ -f "deploy/olly.service" ]; then
        SERVICE_FILE="deploy/olly.service"
    fi

    if [ -n "$SERVICE_FILE" ]; then
        cp "$SERVICE_FILE" /etc/systemd/system/olly.service
        systemctl daemon-reload
        systemctl enable olly.service
        info "Systemd service installed and enabled"
        info "Start with: systemctl start olly"
    fi
else
    warn "systemd not found, skipping service installation"
fi

info "Installation complete!"
echo ""
echo "Next steps:"
echo "  1. Edit config:   vi ${CONFIG_DIR}/base.yaml"
echo "  2. Start agent:   systemctl start olly"
echo "  3. Check status:  systemctl status olly"
echo "  4. View logs:     journalctl -u olly -f"
echo "  5. Health check:  curl localhost:8686/health"
