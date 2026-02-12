// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"go.uber.org/zap"
)

// LogLevel represents log severity.
type LogLevel int

const (
	LevelUnspecified LogLevel = iota
	LevelTrace
	LevelDebug
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

func (l LogLevel) String() string {
	switch l {
	case LevelTrace:
		return "TRACE"
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNSPECIFIED"
	}
}

// LogRecord represents a single log entry.
type LogRecord struct {
	Timestamp   time.Time
	Body        string
	Level       LogLevel
	Attributes  map[string]interface{}
	Resource    map[string]string
	PID         int
	TID         int
	ProcessName string
	TraceID     string
	SpanID      string
	ServiceName string
	Source      string // "file"
	FilePath    string
}

// GetPID implements the correlation.LogRecord interface.
func (r *LogRecord) GetPID() int { return r.PID }

// GetTID implements the correlation.LogRecord interface.
func (r *LogRecord) GetTID() int { return r.TID }

// GetTimestamp implements the correlation.LogRecord interface.
func (r *LogRecord) GetTimestamp() time.Time { return r.Timestamp }

// SetTraceContext implements the correlation.LogRecord interface.
// F1 fix: Also injects trace context as structured attributes so downstream
// systems (Loki, Elasticsearch, Splunk) can correlate log→trace without
// special OTLP support.
func (r *LogRecord) SetTraceContext(traceID, spanID, serviceName string) {
	r.TraceID = traceID
	r.SpanID = spanID
	r.ServiceName = serviceName

	// Inject into attributes for downstream log systems that parse structured fields
	if r.Attributes == nil {
		r.Attributes = make(map[string]interface{})
	}
	r.Attributes["trace_id"] = traceID
	r.Attributes["span_id"] = spanID
	if serviceName != "" {
		r.Attributes["service.name"] = serviceName
	}
	// W3C traceparent format: 00-{trace_id}-{span_id}-01
	r.Attributes["traceparent"] = "00-" + traceID + "-" + spanID + "-01"
}

// HasTraceContext returns true if the log already has trace context.
func (r *LogRecord) HasTraceContext() bool {
	return r.TraceID != ""
}

// Collector manages log collection from multiple sources.
type Collector struct {
	cfg         *config.LogsConfig
	logger      *zap.Logger
	parser      *Parser
	auditParser *AuditParser

	// Sampling and rate limiting
	sampleRate    float64 // 0.0-1.0, 0 = unset (keep all)
	rateLimit     int     // max logs/sec, 0 = unlimited
	tokenCount    atomic.Int64
	lastRefill    atomic.Int64

	mu        sync.RWMutex
	callbacks []func(*LogRecord)
	tailers   []*Tailer

	wg     sync.WaitGroup
	stopCh chan struct{}
}

// NewCollector creates a new log collector.
func NewCollector(cfg *config.LogsConfig, logger *zap.Logger) *Collector {
	c := &Collector{
		cfg:         cfg,
		logger:      logger,
		parser:      NewParser(),
		auditParser: NewAuditParser(),
		stopCh:      make(chan struct{}),
		sampleRate:  cfg.Sampling.Rate,
		rateLimit:   cfg.RateLimit,
	}
	if c.rateLimit > 0 {
		c.tokenCount.Store(int64(c.rateLimit))
		c.lastRefill.Store(time.Now().UnixNano())
	}
	return c
}

// OnLog registers a callback for collected log records.
func (c *Collector) OnLog(fn func(*LogRecord)) {
	c.mu.Lock()
	c.callbacks = append(c.callbacks, fn)
	c.mu.Unlock()
}

func (c *Collector) emit(record *LogRecord) {
	// Apply sampling
	if c.sampleRate > 0 && c.sampleRate < 1.0 {
		if !c.shouldSampleLog() {
			return
		}
	}

	// Apply rate limiting (token bucket)
	if c.rateLimit > 0 && !c.tryConsumeToken() {
		return
	}

	c.mu.RLock()
	cbs := c.callbacks
	c.mu.RUnlock()

	for _, cb := range cbs {
		cb(record)
	}
}

func (c *Collector) shouldSampleLog() bool {
	return rand.Float64() < c.sampleRate
}

func (c *Collector) tryConsumeToken() bool {
	now := time.Now().UnixNano()
	last := c.lastRefill.Load()
	elapsed := now - last

	// Refill tokens every second
	if elapsed >= int64(time.Second) {
		c.tokenCount.Store(int64(c.rateLimit))
		c.lastRefill.Store(now)
	}

	for {
		current := c.tokenCount.Load()
		if current <= 0 {
			return false
		}
		if c.tokenCount.CompareAndSwap(current, current-1) {
			return true
		}
	}
}

// Start begins collecting logs from configured sources.
func (c *Collector) Start(ctx context.Context) error {
	for _, src := range c.cfg.Sources {
		switch src.Type {
		case "file":
			for _, pattern := range src.Paths {
				tailer, err := NewTailer(pattern, src.Excludes, src.Format, c.parser, c.logger)
				if err != nil {
					c.logger.Warn("failed to create tailer", zap.String("pattern", pattern), zap.Error(err))
					continue
				}
				tailer.OnLog(func(record *LogRecord) {
					c.emit(record)
				})
				c.tailers = append(c.tailers, tailer)

				c.wg.Add(1)
				go func(t *Tailer) {
					defer c.wg.Done()
					t.Run(ctx, c.stopCh)
				}(tailer)
			}

		case "audit":
			// Linux audit log (auditd format)
			for _, pattern := range src.Paths {
				tailer, err := NewTailer(pattern, nil, "raw", c.parser, c.logger)
				if err != nil {
					c.logger.Warn("failed to create audit tailer", zap.String("pattern", pattern), zap.Error(err))
					continue
				}
				ap := c.auditParser
				tailer.OnLog(func(record *LogRecord) {
					auditRecord := ap.ParseAuditLine(record.Body)
					if auditRecord != nil {
						c.emit(auditRecord)
					}
				})
				c.tailers = append(c.tailers, tailer)

				c.wg.Add(1)
				go func(t *Tailer) {
					defer c.wg.Done()
					t.Run(ctx, c.stopCh)
				}(tailer)
			}

		case "auth":
			// Auth/secure log (syslog auth format)
			for _, pattern := range src.Paths {
				tailer, err := NewTailer(pattern, nil, "raw", c.parser, c.logger)
				if err != nil {
					// Auth log paths vary by distro; missing files are expected
					c.logger.Debug("auth log not found", zap.String("path", pattern))
					continue
				}
				ap := c.auditParser
				tailer.OnLog(func(record *LogRecord) {
					authRecord := ap.ParseAuthLine(record.Body)
					if authRecord != nil {
						c.emit(authRecord)
					}
				})
				c.tailers = append(c.tailers, tailer)

				c.wg.Add(1)
				go func(t *Tailer) {
					defer c.wg.Done()
					t.Run(ctx, c.stopCh)
				}(tailer)
			}

		default:
			c.logger.Warn("unsupported log source type", zap.String("type", src.Type))
		}
	}

	c.logger.Info("log collector started", zap.Int("sources", len(c.tailers)))
	return nil
}

// Stop halts all log collection.
func (c *Collector) Stop() error {
	close(c.stopCh)
	for _, t := range c.tailers {
		t.Stop()
	}
	c.wg.Wait()
	return nil
}
