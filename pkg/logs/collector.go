// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"context"
	"math/rand/v2"
	"regexp"
	"strings"
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
	Source      string // "file", "journald", "audit", "auth"
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

// ParseLevel parses a level string to LogLevel.
func ParseLevel(s string) LogLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "TRACE":
		return LevelTrace
	case "DEBUG":
		return LevelDebug
	case "INFO":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR", "ERR":
		return LevelError
	case "FATAL", "CRITICAL", "EMERG", "ALERT":
		return LevelFatal
	default:
		return LevelUnspecified
	}
}

// Collector manages log collection from multiple sources.
type Collector struct {
	cfg         *config.LogsConfig
	logger      *zap.Logger
	parser      *Parser
	auditParser *AuditParser
	multiline   *MultilineAssembler

	// Per-source multiline assemblers (index by source position)
	sourceMultiline map[int]*MultilineAssembler

	// Filtering
	includeREs []*regexp.Regexp
	excludeREs []*regexp.Regexp
	minLevel   LogLevel

	// Journald
	journaldReader *JournaldReader

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
		cfg:             cfg,
		logger:          logger,
		parser:          NewParser(),
		auditParser:     NewAuditParser(),
		stopCh:          make(chan struct{}),
		sampleRate:      cfg.Sampling.Rate,
		rateLimit:       cfg.RateLimit,
		sourceMultiline: make(map[int]*MultilineAssembler),
	}
	if c.rateLimit > 0 {
		c.tokenCount.Store(int64(c.rateLimit))
		c.lastRefill.Store(time.Now().UnixNano())
	}
	// Initialize global multiline assembler if configured
	if cfg.Multiline.Enabled {
		c.multiline = NewMultilineAssembler(&cfg.Multiline, func(record *LogRecord) {
			c.emitDirect(record)
		})
	}
	// Compile filter patterns
	for _, p := range cfg.Filter.IncludePatterns {
		if re, err := regexp.Compile(p); err != nil {
			logger.Warn("invalid include pattern", zap.String("pattern", p), zap.Error(err))
		} else {
			c.includeREs = append(c.includeREs, re)
		}
	}
	for _, p := range cfg.Filter.ExcludePatterns {
		if re, err := regexp.Compile(p); err != nil {
			logger.Warn("invalid exclude pattern", zap.String("pattern", p), zap.Error(err))
		} else {
			c.excludeREs = append(c.excludeREs, re)
		}
	}
	if cfg.Filter.MinLevel != "" {
		c.minLevel = ParseLevel(cfg.Filter.MinLevel)
	}
	// Build per-source multiline assemblers
	for i, src := range cfg.Sources {
		if src.Multiline != nil && src.Multiline.Enabled {
			idx := i
			c.sourceMultiline[idx] = NewMultilineAssembler(src.Multiline, func(record *LogRecord) {
				c.emitDirect(record)
			})
		}
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
	c.emitForSource(-1, record)
}

func (c *Collector) emitForSource(sourceIdx int, record *LogRecord) {
	// Apply filtering first (before sampling)
	if c.shouldFilter(record) {
		return
	}

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

	// Route through per-source multiline assembler if available
	if sourceIdx >= 0 {
		if ma, ok := c.sourceMultiline[sourceIdx]; ok {
			ma.Process(record)
			return
		}
	}

	// Route through global multiline assembler if enabled
	if c.multiline != nil {
		c.multiline.Process(record)
		return
	}

	c.emitDirect(record)
}

// shouldFilter returns true if the record should be dropped.
func (c *Collector) shouldFilter(record *LogRecord) bool {
	// Level filtering
	if c.minLevel > LevelUnspecified && record.Level > LevelUnspecified {
		if record.Level < c.minLevel {
			return true
		}
	}

	// Include patterns: if set, record must match at least one
	if len(c.includeREs) > 0 {
		matched := false
		for _, re := range c.includeREs {
			if re.MatchString(record.Body) {
				matched = true
				break
			}
		}
		if !matched {
			return true
		}
	}

	// Exclude patterns: record must not match any
	for _, re := range c.excludeREs {
		if re.MatchString(record.Body) {
			return true
		}
	}

	return false
}

// emitDirect sends a record directly to callbacks (bypasses multiline/sampling).
func (c *Collector) emitDirect(record *LogRecord) {
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
	for i, src := range c.cfg.Sources {
		srcIdx := i
		switch src.Type {
		case "file":
			for _, pattern := range src.Paths {
				tailer, err := NewTailer(pattern, src.Excludes, src.Format, c.parser, c.logger)
				if err != nil {
					c.logger.Warn("failed to create tailer", zap.String("pattern", pattern), zap.Error(err))
					continue
				}
				idx := srcIdx
				tailer.OnLog(func(record *LogRecord) {
					c.emitForSource(idx, record)
				})
				c.tailers = append(c.tailers, tailer)

				c.wg.Add(1)
				go func(t *Tailer) {
					defer c.wg.Done()
					t.Run(ctx, c.stopCh)
				}(tailer)
			}

		case "journald":
			j := NewJournaldReader(src.Paths, c.logger)
			idx := srcIdx
			j.OnLog(func(record *LogRecord) {
				c.emitForSource(idx, record)
			})
			if err := j.Start(ctx); err != nil {
				c.logger.Warn("failed to start journald reader", zap.Error(err))
			} else {
				c.journaldReader = j
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
				idx := srcIdx
				tailer.OnLog(func(record *LogRecord) {
					auditRecord := ap.ParseAuditLine(record.Body)
					if auditRecord != nil {
						c.emitForSource(idx, auditRecord)
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
				idx := srcIdx
				tailer.OnLog(func(record *LogRecord) {
					authRecord := ap.ParseAuthLine(record.Body)
					if authRecord != nil {
						c.emitForSource(idx, authRecord)
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
	if c.journaldReader != nil {
		c.journaldReader.Stop()
	}
	c.wg.Wait()
	// Flush any remaining multiline buffers
	if c.multiline != nil {
		c.multiline.Flush()
	}
	for _, ma := range c.sourceMultiline {
		ma.Flush()
	}
	return nil
}
