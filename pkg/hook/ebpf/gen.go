package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" olly bpf/olly.bpf.c -- -Ibpf/headers -Ibpf
