// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package servicemap

import (
	"testing"
	"time"

	"go.uber.org/zap"
)

func TestRecordSpan(t *testing.T) {
	g := NewGenerator(zap.NewNop())
	g.RecordSpan("api-gateway", "order-service", 8080, "http", false, 50*time.Millisecond)
	g.RecordSpan("api-gateway", "order-service", 8080, "http", false, 100*time.Millisecond)

	edges := g.GetEdges()
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}

	e := edges[0]
	if e.Source != "api-gateway" {
		t.Errorf("expected source api-gateway, got %s", e.Source)
	}
	if e.Destination != "order-service" {
		t.Errorf("expected dest order-service, got %s", e.Destination)
	}
	if e.Protocol != "http" {
		t.Errorf("expected protocol http, got %s", e.Protocol)
	}
	if e.Count != 2 {
		t.Errorf("expected count 2, got %d", e.Count)
	}
	if e.ErrorCount != 0 {
		t.Errorf("expected error count 0, got %d", e.ErrorCount)
	}
}

func TestRecordSpanErrorAccumulation(t *testing.T) {
	g := NewGenerator(zap.NewNop())
	g.RecordSpan("a", "b", 5432, "postgresql", true, 10*time.Millisecond)
	g.RecordSpan("a", "b", 5432, "postgresql", false, 20*time.Millisecond)
	g.RecordSpan("a", "b", 5432, "postgresql", true, 30*time.Millisecond)

	edges := g.GetEdges()
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}

	e := edges[0]
	if e.ErrorCount != 2 {
		t.Errorf("expected 2 errors, got %d", e.ErrorCount)
	}
	if e.Count != 3 {
		t.Errorf("expected count 3, got %d", e.Count)
	}
}

func TestEdgeAvgLatency(t *testing.T) {
	g := NewGenerator(zap.NewNop())
	g.RecordSpan("a", "b", 80, "http", false, 100*time.Millisecond)
	g.RecordSpan("a", "b", 80, "http", false, 200*time.Millisecond)

	edges := g.GetEdges()
	e := edges[0]

	avg := e.AvgLatency()
	expected := 150 * time.Millisecond
	if avg != expected {
		t.Errorf("expected avg latency %v, got %v", expected, avg)
	}
}

func TestEdgeAvgLatencyZeroCalls(t *testing.T) {
	e := &Edge{}
	if e.AvgLatency() != 0 {
		t.Error("expected 0 avg latency for zero calls")
	}
}

func TestEdgeErrorRate(t *testing.T) {
	g := NewGenerator(zap.NewNop())
	g.RecordSpan("a", "b", 80, "http", true, 10*time.Millisecond)
	g.RecordSpan("a", "b", 80, "http", false, 10*time.Millisecond)
	g.RecordSpan("a", "b", 80, "http", true, 10*time.Millisecond)
	g.RecordSpan("a", "b", 80, "http", false, 10*time.Millisecond)

	edges := g.GetEdges()
	e := edges[0]

	rate := e.ErrorRate()
	if rate != 0.5 {
		t.Errorf("expected error rate 0.5, got %f", rate)
	}
}

func TestEdgeErrorRateZeroCalls(t *testing.T) {
	e := &Edge{}
	if e.ErrorRate() != 0 {
		t.Error("expected 0 error rate for zero calls")
	}
}

func TestRecordConnectionAndRecordSpanSameEdge(t *testing.T) {
	g := NewGenerator(zap.NewNop())
	g.RecordConnection("a", "b", 80)
	g.RecordSpan("a", "b", 80, "http", false, 10*time.Millisecond)

	edges := g.GetEdges()
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if edges[0].Count != 2 {
		t.Errorf("expected count 2, got %d", edges[0].Count)
	}
	if edges[0].Protocol != "http" {
		t.Errorf("expected protocol http from RecordSpan, got %s", edges[0].Protocol)
	}
}

func TestMultipleEdges(t *testing.T) {
	g := NewGenerator(zap.NewNop())
	g.RecordSpan("a", "b", 80, "http", false, 10*time.Millisecond)
	g.RecordSpan("a", "c", 5432, "postgresql", false, 20*time.Millisecond)

	edges := g.GetEdges()
	if len(edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(edges))
	}
}
