// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

//go:build linux

package ebpf

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Detect checks whether the current system supports eBPF with the features
// we need (kprobes, ring buffer, CO-RE/BTF). Requires Linux 5.8+.
func Detect() EBPFSupport {
	kver := kernelVersion()

	major, minor, err := parseKernelVersion(kver)
	if err != nil {
		return EBPFSupport{
			Available:     false,
			KernelVersion: kver,
			Reason:        fmt.Sprintf("cannot parse kernel version %q: %v", kver, err),
		}
	}

	// Ring buffer requires 5.8+
	if major < 5 || (major == 5 && minor < 8) {
		return EBPFSupport{
			Available:     false,
			KernelVersion: kver,
			Reason:        fmt.Sprintf("kernel %d.%d < 5.8 (ring buffer requires 5.8+)", major, minor),
		}
	}

	hasBTF := btfAvailable()

	return EBPFSupport{
		Available:     true,
		KernelVersion: kver,
		HasBTF:        hasBTF,
	}
}

// kernelVersion returns the running kernel version string.
func kernelVersion() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "unknown"
	}
	return strings.TrimRight(string(uname.Release[:]), "\x00")
}

// btfAvailable checks if the kernel exposes BTF type information,
// which is required for CO-RE (compile once, run everywhere) BPF programs.
func btfAvailable() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}
