// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

//go:build !linux

package profiling

import (
	"context"
	"fmt"
)

// stubProfiler is a no-op profiler for non-Linux platforms.
type stubProfiler struct {
	cfg *Config
}

func newProfiler(cfg *Config) Profiler {
	return &stubProfiler{cfg: cfg}
}

func (p *stubProfiler) Start(ctx context.Context) error {
	if p.cfg.Logger != nil {
		p.cfg.Logger.Info("CPU profiling not available on this platform")
	}
	return nil
}

func (p *stubProfiler) Stop() error {
	return nil
}

func (p *stubProfiler) OnProfile(fn func(*Profile)) {
	// No-op
}

func (p *stubProfiler) SetServiceResolver(fn func(pid uint32) string) {
	// No-op
}

func (p *stubProfiler) TriggerProfile(req TriggerRequest) error {
	return fmt.Errorf("profiling not available on this platform")
}

func (p *stubProfiler) StopProfile() error {
	return nil
}

func (p *stubProfiler) State() ProfileState {
	return ProfileIdle
}
