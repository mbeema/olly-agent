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

// Sample represents a CPU profiling sample (internal use).
type Sample struct {
	PID       uint32
	TID       uint32
	Stack     []StackFrame
	Timestamp time.Time
	Count     uint64
}

// Profile is an aggregated CPU profile ready for export.
type Profile struct {
	ServiceName string
	Start       time.Time
	End         time.Time
	PProfData   []byte // gzip'd pprof protobuf
}

// Profiler is the interface for CPU profiling.
type Profiler interface {
	Start(ctx context.Context) error
	Stop() error
	OnProfile(fn func(*Profile))
	SetServiceResolver(fn func(pid uint32) string)
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
