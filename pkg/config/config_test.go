package config

import "testing"

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
