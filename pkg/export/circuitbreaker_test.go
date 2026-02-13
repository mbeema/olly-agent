// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package export

import (
	"testing"
	"time"
)

func TestCircuitBreakerStartsClosed(t *testing.T) {
	cb := NewCircuitBreaker(5, 30*time.Second)
	if cb.State() != CircuitClosed {
		t.Errorf("expected CircuitClosed, got %v", cb.State())
	}
}

func TestCircuitBreakerAllowsInClosedState(t *testing.T) {
	cb := NewCircuitBreaker(5, 30*time.Second)
	if !cb.Allow() {
		t.Error("expected Allow() to return true in Closed state")
	}
}

func TestCircuitBreakerOpensAfterThreshold(t *testing.T) {
	cb := NewCircuitBreaker(3, 30*time.Second)
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	if cb.State() != CircuitOpen {
		t.Errorf("expected CircuitOpen after 3 failures, got %v", cb.State())
	}
	if cb.Allow() {
		t.Error("expected Allow() to return false in Open state")
	}
}

func TestCircuitBreakerDoesNotOpenBelowThreshold(t *testing.T) {
	cb := NewCircuitBreaker(5, 30*time.Second)
	for i := 0; i < 4; i++ {
		cb.RecordFailure()
	}
	if cb.State() != CircuitClosed {
		t.Errorf("expected CircuitClosed with 4/5 failures, got %v", cb.State())
	}
}

func TestCircuitBreakerTransitionsToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("expected CircuitOpen, got %v", cb.State())
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)
	if cb.State() != CircuitHalfOpen {
		t.Errorf("expected CircuitHalfOpen after timeout, got %v", cb.State())
	}
}

func TestCircuitBreakerHalfOpenAllowsOneRequest(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	cb.RecordFailure()
	cb.RecordFailure()

	time.Sleep(60 * time.Millisecond)
	if !cb.Allow() {
		t.Error("expected Allow() to return true in HalfOpen state")
	}
}

func TestCircuitBreakerHalfOpenClosesOnSuccess(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	cb.RecordFailure()
	cb.RecordFailure()

	time.Sleep(60 * time.Millisecond)
	cb.Allow() // transitions to HalfOpen
	cb.RecordSuccess()

	if cb.State() != CircuitClosed {
		t.Errorf("expected CircuitClosed after success in HalfOpen, got %v", cb.State())
	}
	if cb.FailureCount() != 0 {
		t.Errorf("expected failure count 0 after success, got %d", cb.FailureCount())
	}
}

func TestCircuitBreakerHalfOpenOpensOnFailure(t *testing.T) {
	cb := NewCircuitBreaker(2, 50*time.Millisecond)
	cb.RecordFailure()
	cb.RecordFailure()

	time.Sleep(60 * time.Millisecond)
	cb.Allow() // transitions to HalfOpen
	cb.RecordFailure()

	if cb.State() != CircuitOpen {
		t.Errorf("expected CircuitOpen after failure in HalfOpen, got %v", cb.State())
	}
}

func TestCircuitBreakerSuccessResetsClosed(t *testing.T) {
	cb := NewCircuitBreaker(5, 30*time.Second)
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()
	if cb.FailureCount() != 0 {
		t.Errorf("expected failure count 0 after success, got %d", cb.FailureCount())
	}
	if cb.State() != CircuitClosed {
		t.Errorf("expected CircuitClosed, got %v", cb.State())
	}
}

func TestCircuitStateString(t *testing.T) {
	tests := []struct {
		state CircuitState
		want  string
	}{
		{CircuitClosed, "closed"},
		{CircuitOpen, "open"},
		{CircuitHalfOpen, "half-open"},
		{CircuitState(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("CircuitState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}
