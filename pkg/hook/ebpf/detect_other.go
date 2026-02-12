// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

//go:build !linux

package ebpf

import (
	"fmt"
	"runtime"
)

// Detect on non-Linux platforms always returns unavailable.
func Detect() EBPFSupport {
	return EBPFSupport{
		Available: false,
		Reason:    fmt.Sprintf("eBPF not supported on %s (requires Linux)", runtime.GOOS),
	}
}
