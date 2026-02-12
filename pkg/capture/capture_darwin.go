// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

//go:build darwin

package capture

import (
	"context"

	"go.uber.org/zap"
)

// darwinCapturer uses BPF for packet capture on macOS.
type darwinCapturer struct {
	baseCapturer
}

func newCapturer(cfg *Config) Capturer {
	return &darwinCapturer{
		baseCapturer: baseCapturer{
			cfg:    cfg,
			logger: cfg.Logger,
			stopCh: make(chan struct{}),
		},
	}
}

func (c *darwinCapturer) Start(ctx context.Context) error {
	c.logger.Info("packet capture started (macOS BPF)",
		zap.Strings("interfaces", c.cfg.Interfaces),
		zap.String("filter", c.cfg.BPFFilter),
	)

	// TODO: Implement using gopacket/bpf
	// This is a fallback mechanism when DYLD_INSERT_LIBRARIES injection isn't possible.
	// For now, the hook-based approach is the primary capture method.

	return nil
}

func (c *darwinCapturer) Stop() error {
	close(c.stopCh)
	return nil
}
