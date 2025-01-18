package ebpf

import "fmt"

// EBPFSupport describes the level of eBPF support available.
type EBPFSupport struct {
	Available     bool
	KernelVersion string
	HasBTF        bool
	Reason        string // non-empty when Available is false
}

// parseKernelVersion extracts major.minor from a kernel version string.
func parseKernelVersion(version string) (major, minor int, err error) {
	n, err := fmt.Sscanf(version, "%d.%d", &major, &minor)
	if err != nil || n != 2 {
		return 0, 0, fmt.Errorf("expected major.minor format, got %q", version)
	}
	return major, minor, nil
}
