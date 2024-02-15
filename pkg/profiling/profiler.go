package profiling

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// StackFrame represents a single frame in a call stack.
type StackFrame struct {
	Function string
	File     string
	Line     int
}

// Sample represents a CPU profiling sample.
type Sample struct {
	PID       uint32
	TID       uint32
	Stack     []StackFrame
	Timestamp time.Time
	Count     uint64
}

// Profiler is the interface for CPU profiling.
type Profiler interface {
	Start(ctx context.Context) error
	Stop() error
	OnSample(fn func(*Sample))
}

// Config holds profiler configuration.
type Config struct {
	SampleRate int           // Hz
	Interval   time.Duration // Report interval
	Logger     *zap.Logger
}

// New creates a platform-appropriate profiler.
func New(cfg *Config) Profiler {
	return newProfiler(cfg)
}
