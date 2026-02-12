// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package metrics

import (
	"context"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// StatsDReceiver listens for StatsD metrics on a UDP socket.
type StatsDReceiver struct {
	listenAddr string
	logger     *zap.Logger

	mu        sync.RWMutex
	callbacks []func(*Metric)

	// Accumulated metrics
	dataMu   sync.Mutex
	counters map[string]*statsdEntry
	gauges   map[string]*statsdEntry
	timers   map[string]*statsdTimerEntry

	conn   *net.UDPConn
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

type statsdEntry struct {
	value  float64
	labels map[string]string
}

type statsdTimerEntry struct {
	values []float64
	labels map[string]string
}

// NewStatsDReceiver creates a new StatsD UDP receiver.
func NewStatsDReceiver(listenAddr string, logger *zap.Logger) *StatsDReceiver {
	return &StatsDReceiver{
		listenAddr: listenAddr,
		logger:     logger,
		counters:   make(map[string]*statsdEntry),
		gauges:     make(map[string]*statsdEntry),
		timers:     make(map[string]*statsdTimerEntry),
	}
}

// OnMetric registers a callback for received StatsD metrics.
func (s *StatsDReceiver) OnMetric(fn func(*Metric)) {
	s.mu.Lock()
	s.callbacks = append(s.callbacks, fn)
	s.mu.Unlock()
}

func (s *StatsDReceiver) emit(m *Metric) {
	s.mu.RLock()
	cbs := s.callbacks
	s.mu.RUnlock()

	for _, cb := range cbs {
		cb(m)
	}
}

// Start begins listening for StatsD metrics and flushing periodically.
func (s *StatsDReceiver) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.listenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn

	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	s.wg.Add(2)
	go s.readLoop(ctx)
	go s.flushLoop(ctx)

	s.logger.Info("statsd receiver started", zap.String("addr", s.listenAddr))
	return nil
}

func (s *StatsDReceiver) readLoop(ctx context.Context) {
	defer s.wg.Done()

	buf := make([]byte, 65535)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if ctx.Err() != nil {
				return
			}
			s.logger.Debug("statsd read error", zap.Error(err))
			continue
		}

		lines := strings.Split(string(buf[:n]), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				s.parseLine(line)
			}
		}
	}
}

// parseLine parses a StatsD line: metric.name:value|type|@rate|#tag1:val1,tag2:val2
func (s *StatsDReceiver) parseLine(line string) {
	// Split off DogStatsD tags: #tag1:val1,tag2:val2
	labels := make(map[string]string)
	if idx := strings.Index(line, "|#"); idx >= 0 {
		tagPart := line[idx+2:]
		line = line[:idx]
		for _, tag := range strings.Split(tagPart, ",") {
			tag = strings.TrimSpace(tag)
			if eqIdx := strings.Index(tag, ":"); eqIdx > 0 {
				labels[tag[:eqIdx]] = tag[eqIdx+1:]
			} else if tag != "" {
				labels[tag] = "true"
			}
		}
	}

	// Split name:value|type|@rate
	colonIdx := strings.Index(line, ":")
	if colonIdx < 0 {
		return
	}
	name := "statsd." + line[:colonIdx]
	rest := line[colonIdx+1:]

	parts := strings.Split(rest, "|")
	if len(parts) < 2 {
		return
	}

	valueStr := parts[0]
	metricType := parts[1]

	value, err := strconv.ParseFloat(valueStr, 64)
	if err != nil {
		return
	}

	// Parse sample rate
	sampleRate := 1.0
	for _, p := range parts[2:] {
		if strings.HasPrefix(p, "@") {
			if sr, err := strconv.ParseFloat(p[1:], 64); err == nil && sr > 0 {
				sampleRate = sr
			}
		}
	}

	// Build a key for accumulation
	key := name + labelsKey(labels)

	s.dataMu.Lock()
	defer s.dataMu.Unlock()

	switch metricType {
	case "c": // counter
		entry, ok := s.counters[key]
		if !ok {
			entry = &statsdEntry{labels: labels}
			s.counters[key] = entry
		}
		entry.value += value / sampleRate

	case "g": // gauge
		entry, ok := s.gauges[key]
		if !ok {
			entry = &statsdEntry{labels: labels}
			s.gauges[key] = entry
		}
		// StatsD gauge: if value starts with + or -, it's a delta
		if len(valueStr) > 0 && (valueStr[0] == '+' || valueStr[0] == '-') {
			entry.value += value
		} else {
			entry.value = value
		}

	case "ms", "h": // timer/histogram
		entry, ok := s.timers[key]
		if !ok {
			entry = &statsdTimerEntry{labels: labels}
			s.timers[key] = entry
		}
		entry.values = append(entry.values, value)
	}
}

func (s *StatsDReceiver) flushLoop(ctx context.Context) {
	defer s.wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.flush()
		case <-ctx.Done():
			s.flush() // final flush
			return
		}
	}
}

func (s *StatsDReceiver) flush() {
	now := time.Now()

	s.dataMu.Lock()
	counters := s.counters
	gauges := s.gauges
	timers := s.timers
	s.counters = make(map[string]*statsdEntry)
	s.gauges = make(map[string]*statsdEntry)
	s.timers = make(map[string]*statsdTimerEntry)
	s.dataMu.Unlock()

	for name, entry := range counters {
		metricName := extractName(name)
		s.emit(&Metric{
			Name:      metricName,
			Type:      Counter,
			Value:     entry.value,
			Timestamp: now,
			Labels:    entry.labels,
		})
	}

	for name, entry := range gauges {
		metricName := extractName(name)
		s.emit(&Metric{
			Name:      metricName,
			Type:      Gauge,
			Value:     entry.value,
			Timestamp: now,
			Labels:    entry.labels,
		})
	}

	for name, entry := range timers {
		metricName := extractName(name)
		if len(entry.values) == 0 {
			continue
		}

		// Emit summary stats for timers
		sum := 0.0
		min := entry.values[0]
		max := entry.values[0]
		for _, v := range entry.values {
			sum += v
			if v < min {
				min = v
			}
			if v > max {
				max = v
			}
		}
		avg := sum / float64(len(entry.values))

		s.emit(&Metric{
			Name:      metricName + ".avg",
			Type:      Gauge,
			Unit:      "ms",
			Value:     math.Round(avg*1000) / 1000,
			Timestamp: now,
			Labels:    entry.labels,
		})
		s.emit(&Metric{
			Name:      metricName + ".count",
			Type:      Counter,
			Value:     float64(len(entry.values)),
			Timestamp: now,
			Labels:    entry.labels,
		})
		s.emit(&Metric{
			Name:      metricName + ".min",
			Type:      Gauge,
			Unit:      "ms",
			Value:     min,
			Timestamp: now,
			Labels:    entry.labels,
		})
		s.emit(&Metric{
			Name:      metricName + ".max",
			Type:      Gauge,
			Unit:      "ms",
			Value:     max,
			Timestamp: now,
			Labels:    entry.labels,
		})
	}
}

// Stop halts the StatsD receiver.
func (s *StatsDReceiver) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.conn != nil {
		s.conn.Close()
	}
	s.wg.Wait()
}

// labelsKey builds a stable string key from labels for map deduplication.
func labelsKey(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteByte('|')
	for k, v := range labels {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(v)
		b.WriteByte(',')
	}
	return b.String()
}

// extractName extracts the metric name from a key (strips label suffix).
func extractName(key string) string {
	if idx := strings.IndexByte(key, '|'); idx > 0 {
		return key[:idx]
	}
	return key
}
