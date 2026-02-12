// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package health

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestHealthEndpoint(t *testing.T) {
	stats := NewStats()
	srv := NewServer(":0", "1.0.0-test", stats, zap.NewNop())

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.handleHealth(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var hr healthResponse
	if err := json.Unmarshal(body, &hr); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if hr.Status != "healthy" {
		t.Errorf("expected status=healthy, got %q", hr.Status)
	}
	if hr.Version != "1.0.0-test" {
		t.Errorf("expected version=1.0.0-test, got %q", hr.Version)
	}
}

func TestReadyEndpoint_NotReady(t *testing.T) {
	stats := NewStats()
	srv := NewServer(":0", "test", stats, zap.NewNop())

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	srv.handleReady(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestReadyEndpoint_Ready(t *testing.T) {
	stats := NewStats()
	srv := NewServer(":0", "test", stats, zap.NewNop())
	srv.SetReady(true)

	req := httptest.NewRequest("GET", "/ready", nil)
	w := httptest.NewRecorder()
	srv.handleReady(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	stats := NewStats()
	stats.SpansExported.Add(42)
	stats.LogsDropped.Add(3)

	srv := NewServer(":0", "test", stats, zap.NewNop())

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	srv.handleMetrics(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "olly_spans_exported_total 42") {
		t.Errorf("expected spans_exported_total 42 in metrics output")
	}
	if !strings.Contains(body, "olly_logs_dropped_total 3") {
		t.Errorf("expected logs_dropped_total 3 in metrics output")
	}
	if !strings.Contains(body, "olly_agent_uptime_seconds") {
		t.Errorf("expected agent_uptime_seconds in metrics output")
	}
}

func TestServerStartStop(t *testing.T) {
	stats := NewStats()
	srv := NewServer("127.0.0.1:0", "test", stats, zap.NewNop())

	if err := srv.Start(context.Background()); err != nil {
		t.Fatalf("start failed: %v", err)
	}

	if err := srv.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
}
