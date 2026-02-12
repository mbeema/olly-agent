// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// Server provides health, readiness, and metrics HTTP endpoints.
type Server struct {
	logger  *zap.Logger
	stats   *Stats
	version string
	addr    string
	ready   atomic.Bool
	server  *http.Server
}

// NewServer creates a health server.
func NewServer(addr, version string, stats *Stats, logger *zap.Logger) *Server {
	return &Server{
		addr:    addr,
		version: version,
		stats:   stats,
		logger:  logger,
	}
}

// SetReady marks the agent as ready to serve traffic.
func (s *Server) SetReady(ready bool) {
	s.ready.Store(ready)
}

// Start begins serving health endpoints.
func (s *Server) Start(_ context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)
	mux.HandleFunc("/metrics", s.handleMetrics)

	s.server = &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	go func() {
		if err := s.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.logger.Error("health server error", zap.Error(err))
		}
	}()

	s.logger.Info("health server started", zap.String("addr", s.addr))
	return nil
}

// Stop gracefully shuts down the health server.
func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

type healthResponse struct {
	Status  string  `json:"status"`
	Version string  `json:"version"`
	Uptime  string  `json:"uptime"`
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	resp := healthResponse{
		Status:  "healthy",
		Version: s.version,
		Uptime:  s.stats.Uptime().Truncate(time.Second).String(),
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleReady(w http.ResponseWriter, _ *http.Request) {
	if !s.ready.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"not_ready"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ready"}`))
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Write([]byte(s.stats.PrometheusMetrics()))
}
