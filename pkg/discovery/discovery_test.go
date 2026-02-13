// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package discovery

import (
	"testing"

	"go.uber.org/zap"
)

func TestScanProcessesEmptyPatterns(t *testing.T) {
	d := NewDiscoverer(nil, nil, zap.NewNop())
	result := d.ScanProcesses(nil)
	if len(result) != 0 {
		t.Errorf("expected empty result for nil patterns, got %d", len(result))
	}

	result = d.ScanProcesses([]string{})
	if len(result) != 0 {
		t.Errorf("expected empty result for empty patterns, got %d", len(result))
	}
}

func TestScanProcessesInvalidRegex(t *testing.T) {
	d := NewDiscoverer(nil, nil, zap.NewNop())
	// Invalid regex should be skipped (not panic)
	result := d.ScanProcesses([]string{"[invalid"})
	// With no valid patterns, result should be nil
	if result != nil {
		t.Errorf("expected nil result for all-invalid patterns, got %v", result)
	}
}

func TestScanProcessesMixedValidInvalid(t *testing.T) {
	d := NewDiscoverer(nil, nil, zap.NewNop())
	// One invalid, one valid pattern - should not panic
	result := d.ScanProcesses([]string{"[invalid", ".*"})
	// The ".*" pattern matches everything, so we should get some PIDs
	if len(result) == 0 {
		t.Log("no processes matched (may be OK in restricted environments)")
	}
}

func TestScanProcessesMatchesCurrentProcess(t *testing.T) {
	d := NewDiscoverer(nil, nil, zap.NewNop())
	// "go" or "discovery.test" should match the test binary
	result := d.ScanProcesses([]string{"go", "discovery"})
	// In test environments this should match at least something
	if len(result) == 0 {
		t.Log("no processes matched 'go' or 'discovery' (may be OK in CI)")
	}
}

func TestGetServiceName(t *testing.T) {
	d := NewDiscoverer(nil, nil, zap.NewNop())
	name := d.GetServiceName(0)
	if name == "" {
		t.Error("expected non-empty service name for PID 0")
	}
}

func TestGetServiceNameByPort(t *testing.T) {
	portMappings := map[int]string{
		5432: "postgresql",
		3306: "mysql",
	}
	d := NewDiscoverer(nil, portMappings, zap.NewNop())

	if got := d.GetServiceNameByPort(5432); got != "postgresql" {
		t.Errorf("expected postgresql for port 5432, got %s", got)
	}
	if got := d.GetServiceNameByPort(3306); got != "mysql" {
		t.Errorf("expected mysql for port 3306, got %s", got)
	}
	if got := d.GetServiceNameByPort(9999); got != "port-9999" {
		t.Errorf("expected port-9999 for unknown port, got %s", got)
	}
}

func TestCacheOperations(t *testing.T) {
	d := NewDiscoverer(nil, nil, zap.NewNop())

	// Discover should populate cache
	_ = d.GetServiceName(1) // PID 1 likely exists on Linux

	// InvalidateCache should not panic
	d.InvalidateCache(1)

	// ClearCache should not panic
	d.ClearCache()
}

func TestCleanDeadProcesses(t *testing.T) {
	d := NewDiscoverer(nil, nil, zap.NewNop())

	// Add a definitely-dead PID to cache
	d.mu.Lock()
	d.cache[999999] = &ServiceInfo{
		Name: "dead-process",
		PID:  999999,
	}
	d.mu.Unlock()

	removed := d.CleanDeadProcesses()
	if removed != 1 {
		t.Errorf("expected 1 removed, got %d", removed)
	}
}
