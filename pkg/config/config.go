package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for the olly agent.
type Config struct {
	ServiceName string          `yaml:"service_name"`
	LogLevel    string          `yaml:"log_level"`
	Hook        HookConfig      `yaml:"hook"`
	Tracing     TracingConfig   `yaml:"tracing"`
	Logs        LogsConfig      `yaml:"logs"`
	Correlation CorrelationConfig `yaml:"correlation"`
	Metrics     MetricsConfig   `yaml:"metrics"`
	Exporters   ExportersConfig `yaml:"exporters"`
	Discovery   DiscoveryConfig `yaml:"discovery"`
	Profiling   ProfilingConfig `yaml:"profiling"`
	Capture     CaptureConfig   `yaml:"capture"`
}

type HookConfig struct {
	Enabled     bool   `yaml:"enabled"`
	SocketPath  string `yaml:"socket_path"`
	LibraryPath string `yaml:"library_path"`
	HTTPPorts   []int  `yaml:"http_ports"`
	Debug       bool   `yaml:"debug"`
	OnDemand    bool   `yaml:"on_demand"`    // Start dormant; activate via 'olly trace start'
	LogCapture  *bool  `yaml:"log_capture"`  // Capture log writes via write() hook (default: true)
}

// LogCaptureEnabled returns whether log capture via write() hook is enabled.
// Defaults to true when not explicitly set.
func (h *HookConfig) LogCaptureEnabled() bool {
	if h.LogCapture == nil {
		return true
	}
	return *h.LogCapture
}

type TracingConfig struct {
	Enabled   bool             `yaml:"enabled"`
	Protocols ProtocolsConfig  `yaml:"protocols"`
}

type ProtocolsConfig struct {
	HTTP     ProtocolToggle `yaml:"http"`
	GRPC     ProtocolToggle `yaml:"grpc"`
	Postgres ProtocolToggle `yaml:"postgres"`
	MySQL    ProtocolToggle `yaml:"mysql"`
	Redis    ProtocolToggle `yaml:"redis"`
	MongoDB  ProtocolToggle `yaml:"mongodb"`
	DNS      ProtocolToggle `yaml:"dns"`
}

type ProtocolToggle struct {
	Enabled bool `yaml:"enabled"`
}

type LogsConfig struct {
	Enabled bool         `yaml:"enabled"`
	Sources []LogSource  `yaml:"sources"`
}

type LogSource struct {
	Type     string   `yaml:"type"` // "file"
	Paths    []string `yaml:"paths"`
	Excludes []string `yaml:"excludes"`
	Format   string   `yaml:"format"` // "auto", "json", "syslog", "combined"
}

type CorrelationConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Strategy string        `yaml:"strategy"` // "pid_tid_timestamp"
	Window   time.Duration `yaml:"window"`
}

type MetricsConfig struct {
	Enabled  bool              `yaml:"enabled"`
	Host     MetricsToggle     `yaml:"host"`
	Process  MetricsToggle     `yaml:"process"`
	Request  RequestMetricsCfg `yaml:"request"`
	Interval time.Duration     `yaml:"interval"`
}

type MetricsToggle struct {
	Enabled bool `yaml:"enabled"`
}

type RequestMetricsCfg struct {
	Enabled  bool      `yaml:"enabled"`
	Buckets  []float64 `yaml:"buckets"`
}

type ExportersConfig struct {
	OTLP   OTLPConfig   `yaml:"otlp"`
	Stdout StdoutConfig `yaml:"stdout"`
}

type OTLPConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	Protocol string `yaml:"protocol"` // "grpc" or "http"
	Insecure bool   `yaml:"insecure"`
	Headers  map[string]string `yaml:"headers"`
}

type StdoutConfig struct {
	Enabled bool   `yaml:"enabled"`
	Format  string `yaml:"format"` // "text" or "json"
}

type DiscoveryConfig struct {
	Enabled      bool           `yaml:"enabled"`
	EnvVars      []string       `yaml:"env_vars"`
	PortMappings map[int]string `yaml:"port_mappings"`
}

type ProfilingConfig struct {
	Enabled    bool          `yaml:"enabled"`
	SampleRate int           `yaml:"sample_rate"` // Hz
	Interval   time.Duration `yaml:"interval"`
}

type CaptureConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Interfaces []string `yaml:"interfaces"`
	BPFFilter  string   `yaml:"bpf_filter"`
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// DefaultConfig returns a configuration with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		ServiceName: "auto",
		LogLevel:    "info",
		Hook: HookConfig{
			Enabled:    true,
			SocketPath: "/var/run/olly/hook.sock",
			HTTPPorts:  []int{80, 443, 8080, 8443, 3000, 5000, 8000},
		},
		Tracing: TracingConfig{
			Enabled: true,
			Protocols: ProtocolsConfig{
				HTTP:     ProtocolToggle{Enabled: true},
				GRPC:     ProtocolToggle{Enabled: true},
				Postgres: ProtocolToggle{Enabled: true},
				MySQL:    ProtocolToggle{Enabled: true},
				Redis:    ProtocolToggle{Enabled: true},
				MongoDB:  ProtocolToggle{Enabled: true},
				DNS:      ProtocolToggle{Enabled: true},
			},
		},
		Logs: LogsConfig{
			Enabled: true,
		},
		Correlation: CorrelationConfig{
			Enabled:  true,
			Strategy: "pid_tid_timestamp",
			Window:   100 * time.Millisecond,
		},
		Metrics: MetricsConfig{
			Enabled:  true,
			Host:     MetricsToggle{Enabled: true},
			Process:  MetricsToggle{Enabled: true},
			Request:  RequestMetricsCfg{
				Enabled: true,
				Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			Interval: 15 * time.Second,
		},
		Exporters: ExportersConfig{
			OTLP: OTLPConfig{
				Enabled:  true,
				Endpoint: "localhost:4317",
				Protocol: "grpc",
				Insecure: true,
			},
			Stdout: StdoutConfig{
				Enabled: false,
				Format:  "text",
			},
		},
		Discovery: DiscoveryConfig{
			Enabled: true,
			EnvVars: []string{
				"OTEL_SERVICE_NAME",
				"SERVICE_NAME",
				"DD_SERVICE",
				"APP_NAME",
			},
			PortMappings: map[int]string{
				3306:  "mysql",
				5432:  "postgresql",
				6379:  "redis",
				27017: "mongodb",
				9092:  "kafka",
				5672:  "rabbitmq",
			},
		},
		Profiling: ProfilingConfig{
			Enabled:    false,
			SampleRate: 99,
			Interval:   10 * time.Second,
		},
		Capture: CaptureConfig{
			Enabled: false,
		},
	}
}

// LoadDir loads signal-specific YAML files from a directory and merges them
// into a single Config. Expected files:
//   - base.yaml    → service_name, log_level, hook, exporters, discovery
//   - traces.yaml  → tracing, correlation
//   - metrics.yaml → metrics
//   - logs.yaml    → logs
//   - profiles.yaml → profiling
//
// Missing files are silently ignored (defaults apply).
func LoadDir(dir string) (*Config, error) {
	cfg := DefaultConfig()

	// Load base config first (common settings)
	if err := loadFileInto(filepath.Join(dir, "base.yaml"), cfg); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load base.yaml: %w", err)
	}

	// Signal-specific overlays
	signalFiles := []string{"traces.yaml", "metrics.yaml", "logs.yaml", "profiles.yaml"}
	for _, f := range signalFiles {
		if err := loadFileInto(filepath.Join(dir, f), cfg); err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("load %s: %w", f, err)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return cfg, nil
}

// loadFileInto reads a YAML file and unmarshals it into an existing Config,
// overwriting only the fields present in the file.
func loadFileInto(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, cfg)
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c.Hook.Enabled && c.Hook.SocketPath == "" {
		return fmt.Errorf("hook.socket_path is required when hook is enabled")
	}

	if c.Exporters.OTLP.Enabled {
		if c.Exporters.OTLP.Endpoint == "" {
			return fmt.Errorf("exporters.otlp.endpoint is required when OTLP is enabled")
		}
		if c.Exporters.OTLP.Protocol != "grpc" && c.Exporters.OTLP.Protocol != "http" {
			return fmt.Errorf("exporters.otlp.protocol must be 'grpc' or 'http'")
		}
	}

	if c.Correlation.Window < time.Millisecond {
		return fmt.Errorf("correlation.window must be at least 1ms")
	}

	if c.Profiling.Enabled && c.Profiling.SampleRate <= 0 {
		return fmt.Errorf("profiling.sample_rate must be positive")
	}

	return nil
}
