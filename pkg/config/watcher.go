// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package config

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// Watcher monitors a config directory for YAML file changes and triggers
// a full config reload with debouncing.
type Watcher struct {
	dir      string
	onChange func(*Config, string)
	logger   *zap.Logger

	watcher *fsnotify.Watcher
	mu      sync.Mutex
	stopCh  chan struct{}
}

// NewWatcher creates a config directory watcher.
// onChange is called with the merged config and the name of the changed file.
func NewWatcher(dir string, onChange func(*Config, string), logger *zap.Logger) *Watcher {
	return &Watcher{
		dir:      dir,
		onChange: onChange,
		logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// Start begins watching the config directory for changes.
func (w *Watcher) Start(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	w.watcher = fsw

	if err := fsw.Add(w.dir); err != nil {
		fsw.Close()
		return err
	}

	go w.loop(ctx)
	w.logger.Info("config watcher started", zap.String("dir", w.dir))
	return nil
}

// Stop shuts down the watcher.
func (w *Watcher) Stop() {
	close(w.stopCh)
	if w.watcher != nil {
		w.watcher.Close()
	}
}

func (w *Watcher) loop(ctx context.Context) {
	var debounceTimer *time.Timer
	var lastFile string

	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			// Only react to YAML file writes/creates
			if !strings.HasSuffix(event.Name, ".yaml") && !strings.HasSuffix(event.Name, ".yml") {
				continue
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			lastFile = filepath.Base(event.Name)
			w.logger.Debug("config file changed", zap.String("file", lastFile))

			// Debounce: reset timer on each event
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			debounceTimer = time.AfterFunc(500*time.Millisecond, func() {
				w.reload(lastFile)
			})

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.logger.Warn("config watcher error", zap.Error(err))

		case <-ctx.Done():
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return

		case <-w.stopCh:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return
		}
	}
}

func (w *Watcher) reload(changedFile string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	cfg, err := LoadDir(w.dir)
	if err != nil {
		w.logger.Error("config reload failed", zap.String("file", changedFile), zap.Error(err))
		return
	}

	w.logger.Info("config reloaded", zap.String("trigger", changedFile))
	w.onChange(cfg, changedFile)
}
