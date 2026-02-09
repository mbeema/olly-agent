BINARY := olly
HOOK_LIB := lib/libolly.so
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildDate=$(BUILD_DATE)"

.PHONY: all build build-linux hook clean test lint run

all: hook build

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/olly

build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY)-linux-amd64 ./cmd/olly

hook:
	@mkdir -p lib
	$(CC) -shared -fPIC -O2 -o $(HOOK_LIB) pkg/hook/c/libolly.c -ldl -lpthread

clean:
	rm -rf bin/ lib/
	go clean

test:
	go test -race ./pkg/...

test-coverage:
	go test -race -coverprofile=coverage.out ./pkg/...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

run: all
	sudo LD_PRELOAD=$(HOOK_LIB) bin/$(BINARY) --config configs/olly.yaml

fmt:
	go fmt ./...
	goimports -w .

deps:
	go mod tidy
	go mod download
