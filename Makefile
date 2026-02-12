# Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
# Author: Madhukar Beema, Distinguished Engineer
BINARY := olly
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)"

.PHONY: all build build-linux generate clean test lint run docker helm-package install

all: build

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/olly

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 ./cmd/olly

# Generate eBPF bytecode from C source. Requires clang + linux headers.
# Only needed when pkg/hook/ebpf/bpf/olly.bpf.c changes.
# Generated files are committed to the repo so normal builds don't need clang.
generate:
	go generate ./pkg/hook/ebpf/

clean:
	rm -rf bin/
	go clean

test:
	go test -race ./pkg/...

test-coverage:
	go test -race -coverprofile=coverage.out ./pkg/...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

run: build
	sudo bin/$(BINARY) --config configs/olly.yaml

fmt:
	go fmt ./...
	goimports -w .

deps:
	go mod tidy
	go mod download

# Docker
docker:
	docker build -t $(BINARY):$(VERSION) .

# Helm
helm-package:
	helm package deploy/helm/olly/

helm-template:
	helm template olly deploy/helm/olly/

# Install (Linux only)
install: build-linux
	sudo deploy/install.sh
