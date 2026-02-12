# Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
# Author: Madhukar Beema, Distinguished Engineer
# Stage 1: Build
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X main.version=$(git describe --tags --always --dirty 2>/dev/null || echo dev) \
              -X main.commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown) \
              -X main.buildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /olly ./cmd/olly

# Stage 2: Runtime
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S olly && adduser -S olly -G olly

COPY --from=builder /olly /usr/local/bin/olly

# Default configs
COPY deploy/configs/ /etc/olly/

# Health check port
EXPOSE 8686

# Runtime directories
RUN mkdir -p /var/run/olly /var/log/olly && \
    chown -R olly:olly /var/run/olly /var/log/olly /etc/olly

ENTRYPOINT ["/usr/local/bin/olly", "--config-dir", "/etc/olly/"]
