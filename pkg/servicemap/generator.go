// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package servicemap

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// Edge represents a connection between two services.
type Edge struct {
	Source      string
	Destination string
	Port        uint16
	Count       uint64
	LastSeen    time.Time
}

// Generator builds a service dependency graph from observed connections.
type Generator struct {
	logger *zap.Logger

	mu    sync.RWMutex
	edges map[string]*Edge // key: "src->dst:port"
}

// NewGenerator creates a new service map generator.
func NewGenerator(logger *zap.Logger) *Generator {
	return &Generator{
		logger: logger,
		edges:  make(map[string]*Edge),
	}
}

// RecordConnection records a connection between two services.
func (g *Generator) RecordConnection(source, destination string, port uint16) {
	key := fmt.Sprintf("%s->%s:%d", source, destination, port)

	g.mu.Lock()
	edge, ok := g.edges[key]
	if !ok {
		edge = &Edge{
			Source:      source,
			Destination: destination,
			Port:        port,
		}
		g.edges[key] = edge
	}
	edge.Count++
	edge.LastSeen = time.Now()
	g.mu.Unlock()
}

// GetEdges returns all edges in the service map.
func (g *Generator) GetEdges() []*Edge {
	g.mu.RLock()
	defer g.mu.RUnlock()

	edges := make([]*Edge, 0, len(g.edges))
	for _, e := range g.edges {
		edges = append(edges, &Edge{
			Source:      e.Source,
			Destination: e.Destination,
			Port:        e.Port,
			Count:       e.Count,
			LastSeen:    e.LastSeen,
		})
	}
	return edges
}

// GetServices returns all unique service names.
func (g *Generator) GetServices() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	services := make(map[string]bool)
	for _, e := range g.edges {
		services[e.Source] = true
		services[e.Destination] = true
	}

	result := make([]string, 0, len(services))
	for s := range services {
		result = append(result, s)
	}
	return result
}

// ExportDOT generates a Graphviz DOT representation of the service map.
func (g *Generator) ExportDOT() string {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var sb strings.Builder
	sb.WriteString("digraph ServiceMap {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box, style=rounded];\n\n")

	// Collect unique services
	services := make(map[string]bool)
	for _, e := range g.edges {
		services[e.Source] = true
		services[e.Destination] = true
	}

	// Write nodes
	for s := range services {
		label := strings.ReplaceAll(s, "\"", "\\\"")
		sb.WriteString(fmt.Sprintf("  \"%s\";\n", label))
	}
	sb.WriteString("\n")

	// Write edges
	for _, e := range g.edges {
		src := strings.ReplaceAll(e.Source, "\"", "\\\"")
		dst := strings.ReplaceAll(e.Destination, "\"", "\\\"")
		sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"port %d\\n%d calls\"];\n",
			src, dst, e.Port, e.Count))
	}

	sb.WriteString("}\n")
	return sb.String()
}

// CleanStale removes edges that haven't been seen in maxAge.
func (g *Generator) CleanStale(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	g.mu.Lock()
	for key, e := range g.edges {
		if e.LastSeen.Before(cutoff) {
			delete(g.edges, key)
			removed++
		}
	}
	g.mu.Unlock()

	return removed
}

// EdgeCount returns the number of edges.
func (g *Generator) EdgeCount() int {
	g.mu.RLock()
	n := len(g.edges)
	g.mu.RUnlock()
	return n
}
