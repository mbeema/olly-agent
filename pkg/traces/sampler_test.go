package traces

import (
	"testing"
)

func TestSamplerKeepAll(t *testing.T) {
	s := NewSampler(1.0)
	for i := 0; i < 100; i++ {
		traceID := GenerateTraceID()
		if !s.ShouldSample(traceID, false) {
			t.Fatalf("rate=1.0 should keep all traces")
		}
	}
}

func TestSamplerDropAll(t *testing.T) {
	s := NewSampler(0.0)
	for i := 0; i < 100; i++ {
		traceID := GenerateTraceID()
		if s.ShouldSample(traceID, false) {
			t.Fatalf("rate=0.0 should drop all non-error traces")
		}
	}
}

func TestSamplerAlwaysKeepErrors(t *testing.T) {
	s := NewSampler(0.0)
	traceID := GenerateTraceID()
	if !s.ShouldSample(traceID, true) {
		t.Fatal("errors should always be kept even at rate=0")
	}
}

func TestSamplerDeterministic(t *testing.T) {
	s := NewSampler(0.5)
	traceID := GenerateTraceID()
	first := s.ShouldSample(traceID, false)
	for i := 0; i < 100; i++ {
		if s.ShouldSample(traceID, false) != first {
			t.Fatal("same traceID should always get the same sampling decision")
		}
	}
}

func TestSamplerApproximateRate(t *testing.T) {
	s := NewSampler(0.1) // 10%
	kept := 0
	total := 10000
	for i := 0; i < total; i++ {
		traceID := GenerateTraceID()
		if s.ShouldSample(traceID, false) {
			kept++
		}
	}
	rate := float64(kept) / float64(total)
	// Allow 5% tolerance
	if rate < 0.05 || rate > 0.15 {
		t.Errorf("expected ~10%% sample rate, got %.1f%% (%d/%d)", rate*100, kept, total)
	}
}

func TestSamplerInvalidTraceID(t *testing.T) {
	s := NewSampler(0.5)
	// Short traceID should be kept
	if !s.ShouldSample("abc", false) {
		t.Error("invalid traceID should be kept")
	}
	// Invalid hex should be kept
	if !s.ShouldSample("zzzzzzzzzzzzzzzz", false) {
		t.Error("invalid hex traceID should be kept")
	}
}

func TestSamplerRate(t *testing.T) {
	s := NewSampler(0.42)
	if s.Rate() != 0.42 {
		t.Errorf("expected rate 0.42, got %f", s.Rate())
	}
}
