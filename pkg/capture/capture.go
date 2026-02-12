// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package capture

import (
	"context"
	"sync"

	"go.uber.org/zap"
)

// Packet represents a captured network packet.
type Packet struct {
	Timestamp int64
	SrcIP     string
	DstIP     string
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Payload   []byte
	Length    int
}

// Capturer is the interface for packet capture.
type Capturer interface {
	Start(ctx context.Context) error
	Stop() error
	OnPacket(fn func(*Packet))
}

// Config holds capture configuration.
type Config struct {
	Interfaces []string
	BPFFilter  string
	Logger     *zap.Logger
}

// baseCapturer provides common functionality.
type baseCapturer struct {
	cfg       *Config
	logger    *zap.Logger
	mu        sync.RWMutex
	callbacks []func(*Packet)
	stopCh    chan struct{}
}

func (c *baseCapturer) OnPacket(fn func(*Packet)) {
	c.mu.Lock()
	c.callbacks = append(c.callbacks, fn)
	c.mu.Unlock()
}

func (c *baseCapturer) emit(pkt *Packet) {
	c.mu.RLock()
	cbs := c.callbacks
	c.mu.RUnlock()

	for _, cb := range cbs {
		cb(pkt)
	}
}

// New creates a platform-appropriate packet capturer.
func New(cfg *Config) Capturer {
	return newCapturer(cfg)
}
