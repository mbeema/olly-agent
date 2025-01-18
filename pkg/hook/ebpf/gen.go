package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64,arm64 -cflags "-O2 -g -Wall -Werror" olly bpf/olly.bpf.c -- -I bpf
