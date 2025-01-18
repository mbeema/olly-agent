package logs

import (
	"context"
	"sync"
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

	mu        sync.RWMutex
	callbacks []func(*LogRecord)
	tailers   []*Tailer

	wg     sync.WaitGroup
	stopCh chan struct{}
}

// NewCollector creates a new log collector.
func NewCollector(cfg *config.LogsConfig, logger *zap.Logger) *Collector {
	return &Collector{
		cfg:         cfg,
		logger:      logger,
		parser:      NewParser(),
		auditParser: NewAuditParser(),
		stopCh:      make(chan struct{}),
	}
}

// OnLog registers a callback for collected log records.
func (c *Collector) OnLog(fn func(*LogRecord)) {
	c.mu.Lock()
	c.callbacks = append(c.callbacks, fn)
	c.mu.Unlock()
}

func (c *Collector) emit(record *LogRecord) {
	c.mu.RLock()
	cbs := c.callbacks
	c.mu.RUnlock()

	for _, cb := range cbs {
		cb(record)
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
