// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mbeema/olly/pkg/agent"
	"github.com/mbeema/olly/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	var (
		configPath  string
		configDir   string
		logLevel    string
		showVersion bool
	)

	flag.StringVar(&configPath, "config", "", "path to configuration file")
	flag.StringVar(&configDir, "config-dir", "", "path to config directory (multi-file mode with auto-reload)")
	flag.StringVar(&logLevel, "log-level", "", "log level (debug, info, warn, error)")
	flag.BoolVar(&showVersion, "version", false, "show version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("olly %s (commit: %s, built: %s)\n", version, commit, buildDate)
		os.Exit(0)
	}

	// Load configuration
	var cfg *config.Config
	var err error
	if configDir != "" {
		cfg, err = config.LoadDir(configDir)
	} else {
		cfg, err = loadConfig(configPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Override log level from CLI
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}

	// Initialize logger
	logger, err := newLogger(cfg.LogLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	logger.Info("starting olly agent",
		zap.String("version", version),
		zap.String("commit", commit),
	)

	// Create and start agent
	a, err := agent.New(cfg, logger)
	if err != nil {
		logger.Fatal("failed to create agent", zap.Error(err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := a.Start(ctx); err != nil {
		logger.Fatal("failed to start agent", zap.Error(err))
	}

	// Start config directory watcher if --config-dir is set
	var watcher *config.Watcher
	if configDir != "" {
		watcher = config.NewWatcher(configDir, func(newCfg *config.Config, changedFile string) {
			if err := a.Reload(newCfg); err != nil {
				logger.Error("failed to apply reloaded config",
					zap.String("file", changedFile),
					zap.Error(err),
				)
			}
		}, logger)
		if err := watcher.Start(ctx); err != nil {
			logger.Fatal("failed to start config watcher", zap.Error(err))
		}
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// SIGHUP for config reload (single-file mode)
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)

	for {
		select {
		case sig := <-sigCh:
			logger.Info("received shutdown signal", zap.String("signal", sig.String()))
			if watcher != nil {
				watcher.Stop()
			}
			cancel()

			// Graceful shutdown with 30s timeout
			shutdownDone := make(chan struct{})
			go func() {
				if err := a.Stop(); err != nil {
					logger.Error("error during shutdown", zap.Error(err))
				}
				close(shutdownDone)
			}()

			select {
			case <-shutdownDone:
				logger.Info("olly agent stopped")
			case <-time.After(30 * time.Second):
				logger.Error("shutdown timed out after 30s, forcing exit")
				os.Exit(1)
			}
			return

		case <-hupCh:
			logger.Info("received SIGHUP, reloading configuration")
			var newCfg *config.Config
			var err error
			if configDir != "" {
				newCfg, err = config.LoadDir(configDir)
			} else {
				newCfg, err = loadConfig(configPath)
			}
			if err != nil {
				logger.Error("failed to reload config", zap.Error(err))
				continue
			}
			if err := a.Reload(newCfg); err != nil {
				logger.Error("failed to apply new config", zap.Error(err))
			} else {
				logger.Info("configuration reloaded successfully")
			}
		}
	}
}

func loadConfig(path string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}

	// Try default locations
	defaults := []string{
		"configs/olly.yaml",
		"/etc/olly/olly.yaml",
		"/etc/olly.yaml",
	}
	for _, p := range defaults {
		if _, err := os.Stat(p); err == nil {
			return config.Load(p)
		}
	}

	// Use defaults
	cfg := config.DefaultConfig()
	return cfg, nil
}

func newLogger(level string) (*zap.Logger, error) {
	var zapLevel zapcore.Level
	switch level {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		zapLevel = zapcore.InfoLevel
	}

	cfg := zap.Config{
		Level:            zap.NewAtomicLevelAt(zapLevel),
		Encoding:         "console",
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		OutputPaths:      []string{"stderr"},
		ErrorOutputPaths: []string{"stderr"},
	}
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	return cfg.Build()
}

