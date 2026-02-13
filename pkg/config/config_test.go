// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package config

import (
	"os"
	"testing"
	"time"
)

func TestLogCaptureEnabledDefault(t *testing.T) {
	cfg := HookConfig{}
	if !cfg.LogCaptureEnabled() {
		t.Error("LogCaptureEnabled should default to true when LogCapture is nil")
	}
}

func TestLogCaptureEnabledExplicitTrue(t *testing.T) {
	v := true
	cfg := HookConfig{LogCapture: &v}
	if !cfg.LogCaptureEnabled() {
		t.Error("LogCaptureEnabled should return true when set to true")
	}
}

func TestLogCaptureEnabledExplicitFalse(t *testing.T) {
	v := false
	cfg := HookConfig{LogCapture: &v}
	if cfg.LogCaptureEnabled() {
		t.Error("LogCaptureEnabled should return false when set to false")
	}
}

func TestDefaultConfigLogCapture(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Hook.LogCaptureEnabled() {
		t.Error("DefaultConfig should have LogCapture enabled by default")
	}
}

// TestParseFloat tests the B9 fix (strconv.ParseFloat instead of reflect)
// indirectly through ApplyEnvOverrides using the OLLY_TRACING_SAMPLING_RATE
// environment variable.
func TestParseFloat(t *testing.T) {
	tests := []struct {
		name     string
		envVal   string
		wantRate float64
		wantSet  bool // whether the env value should override the default
	}{
		{"valid float 0.5", "0.5", 0.5, true},
		{"valid float 1.0", "1.0", 1.0, true},
		{"valid float 0.0", "0.0", 0.0, true},
		{"valid integer 1", "1", 1.0, true},
		{"valid small float", "0.001", 0.001, true},
		{"invalid string", "notanumber", 1.0, false},   // default preserved
		{"whitespace padded", "  0.75  ", 0.75, true},   // TrimSpace in parseFloat
		{"empty string", "", 1.0, false},                 // empty = not set
		{"invalid with letters", "0.5abc", 1.0, false},  // strconv rejects this
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			// Default sampling rate is 1.0
			if cfg.Tracing.Sampling.Rate != 1.0 {
				t.Fatalf("default rate = %v, want 1.0", cfg.Tracing.Sampling.Rate)
			}

			if tt.envVal != "" {
				os.Setenv("OLLY_TRACING_SAMPLING_RATE", tt.envVal)
				defer os.Unsetenv("OLLY_TRACING_SAMPLING_RATE")
			} else {
				os.Unsetenv("OLLY_TRACING_SAMPLING_RATE")
			}

			cfg.ApplyEnvOverrides()

			if cfg.Tracing.Sampling.Rate != tt.wantRate {
				t.Errorf("Tracing.Sampling.Rate = %v, want %v", cfg.Tracing.Sampling.Rate, tt.wantRate)
			}
		})
	}
}

// TestValidateSamplingRate tests the B10 fix: Validate() rejects sampling rates
// outside the 0.0-1.0 range for both tracing and logs.
func TestValidateSamplingRate(t *testing.T) {
	// Helper to build a valid config with specific sampling rates.
	makeConfig := func(tracingRate, logsRate float64) *Config {
		cfg := DefaultConfig()
		cfg.Tracing.Sampling.Rate = tracingRate
		cfg.Logs.Sampling.Rate = logsRate
		// Ensure correlation window passes validation
		cfg.Correlation.Window = 100 * time.Millisecond
		return cfg
	}

	tests := []struct {
		name        string
		tracingRate float64
		logsRate    float64
		wantErr     bool
	}{
		{"both valid 1.0", 1.0, 1.0, false},
		{"both valid 0.0", 0.0, 0.0, false},
		{"both valid mid", 0.5, 0.75, false},
		{"tracing negative", -0.1, 1.0, true},
		{"tracing above 1", 1.1, 1.0, true},
		{"tracing way above", 100.0, 1.0, true},
		{"logs negative", 1.0, -0.5, true},
		{"logs above 1", 1.0, 2.0, true},
		{"both negative", -1.0, -1.0, true},
		{"both above 1", 5.0, 5.0, true},
		{"boundary 0.0", 0.0, 1.0, false},
		{"boundary 1.0", 1.0, 0.0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := makeConfig(tt.tracingRate, tt.logsRate)
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Errorf("Validate() = nil, want error for tracing=%v, logs=%v", tt.tracingRate, tt.logsRate)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Validate() = %v, want nil for tracing=%v, logs=%v", err, tt.tracingRate, tt.logsRate)
			}
		})
	}
}
