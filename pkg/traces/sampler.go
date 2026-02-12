// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package traces

import (
	"encoding/binary"
	"encoding/hex"
)

// Sampler implements deterministic head-based trace sampling.
// Sampling is based on traceID hash, so the same traceID always gets
// the same decision across services.
type Sampler struct {
	rate      float64
	threshold uint64
}

// NewSampler creates a sampler with the given rate (0.0-1.0).
// Rate of 1.0 means keep all traces. Rate of 0.0 means drop all.
func NewSampler(rate float64) *Sampler {
	if rate <= 0 {
		return &Sampler{rate: 0, threshold: 0}
	}
	if rate >= 1.0 {
		return &Sampler{rate: 1.0, threshold: ^uint64(0)}
	}
	return &Sampler{
		rate:      rate,
		threshold: uint64(rate * float64(^uint64(0))),
	}
}

// ShouldSample returns true if the trace should be kept.
// Uses the first 8 bytes of the traceID as a deterministic hash.
func (s *Sampler) ShouldSample(traceID string, isError bool) bool {
	// Always keep errors
	if isError {
		return true
	}

	// Rate 1.0 = keep all
	if s.rate >= 1.0 {
		return true
	}

	// Rate 0.0 = drop all (except errors, handled above)
	if s.rate <= 0 {
		return false
	}

	// Decode first 8 bytes of traceID to get a deterministic hash
	if len(traceID) < 16 {
		return true // invalid traceID, keep it
	}
	b, err := hex.DecodeString(traceID[:16])
	if err != nil {
		return true // invalid hex, keep it
	}

	hash := binary.BigEndian.Uint64(b)
	return hash <= s.threshold
}

// Rate returns the configured sampling rate.
func (s *Sampler) Rate() float64 {
	return s.rate
}
