package profiling

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// ProfileType identifies the kind of profile.
type ProfileType int

const (
	ProfileCPU ProfileType = iota
	ProfileMemory
)

func (t ProfileType) String() string {
	switch t {
	case ProfileCPU:
		return "cpu"
	case ProfileMemory:
		return "memory"
	default:
		return "unknown"
	}
}

// ProfileState represents the on-demand profiling state machine.
type ProfileState int

const (
	ProfileIdle   ProfileState = iota // No profiling active (zero overhead)
	ProfileActive                     // Profiling in progress
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
	ProfileType ProfileType
	Start       time.Time
	End         time.Time
	PProfData   []byte // gzip'd pprof protobuf
}

// TriggerRequest describes an on-demand profiling request.
type TriggerRequest struct {
	Types    []ProfileType // CPU, Memory, or both
	Duration time.Duration // How long to profile (auto-stop)
	PIDs     []uint32      // Specific PIDs (empty = system-wide)
}

// Profiler is the interface for CPU and memory profiling.
// Supports both always-on (config-driven) and on-demand (API-driven) modes.
type Profiler interface {
	// Start begins the profiler in the configured mode.
	// In on-demand mode, this starts idle with zero overhead.
	Start(ctx context.Context) error
	Stop() error
	OnProfile(fn func(*Profile))
	SetServiceResolver(fn func(pid uint32) string)

	// On-demand profiling
	TriggerProfile(req TriggerRequest) error
	StopProfile() error
	State() ProfileState
}

// Config holds profiler configuration.
type Config struct {
	SampleRate int           // Hz
	Interval   time.Duration // Report interval
	OnDemand   bool          // If true, start idle; profile only when triggered
	Logger     *zap.Logger
}

// New creates a platform-appropriate profiler.
func New(cfg *Config) Profiler {
	return newProfiler(cfg)
}
