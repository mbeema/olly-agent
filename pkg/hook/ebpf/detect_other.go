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
