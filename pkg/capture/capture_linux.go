// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

//go:build linux

package capture

import (
	"context"

	"go.uber.org/zap"
)

// linuxCapturer uses AF_PACKET for packet capture on Linux.
type linuxCapturer struct {
	baseCapturer
}

func newCapturer(cfg *Config) Capturer {
	return &linuxCapturer{
		baseCapturer: baseCapturer{
			cfg:    cfg,
			logger: cfg.Logger,
			stopCh: make(chan struct{}),
		},
	}
}

func (c *linuxCapturer) Start(ctx context.Context) error {
	c.logger.Info("packet capture started (Linux AF_PACKET)",
		zap.Strings("interfaces", c.cfg.Interfaces),
		zap.String("filter", c.cfg.BPFFilter),
	)

	// TODO: Implement using gopacket/afpacket
	// This is a fallback mechanism when LD_PRELOAD injection isn't possible.
	// For now, the hook-based approach is the primary capture method.

	return nil
}

func (c *linuxCapturer) Stop() error {
	close(c.stopCh)
	return nil
}
