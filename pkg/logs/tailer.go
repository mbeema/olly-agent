// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"bufio"
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

// Tailer watches and tails log files, handling rotation.
type Tailer struct {
	pattern  string
	excludes []string
	format   string
	parser   *Parser
	logger   *zap.Logger

	mu        sync.RWMutex
	callbacks []func(*LogRecord)
	files     map[string]*tailedFile
	watcher   *fsnotify.Watcher
}

type tailedFile struct {
	path    string
	file    *os.File
	offset  int64
	inode   uint64
	reader  *bufio.Reader
}

// NewTailer creates a new file tailer.
func NewTailer(pattern string, excludes []string, format string, parser *Parser, logger *zap.Logger) (*Tailer, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	return &Tailer{
		pattern:  pattern,
		excludes: excludes,
		format:   format,
		parser:   parser,
		logger:   logger,
		files:    make(map[string]*tailedFile),
		watcher:  watcher,
	}, nil
}

// OnLog registers a callback for log records from this tailer.
func (t *Tailer) OnLog(fn func(*LogRecord)) {
	t.mu.Lock()
	t.callbacks = append(t.callbacks, fn)
	t.mu.Unlock()
}

func (t *Tailer) emit(record *LogRecord) {
	t.mu.RLock()
	cbs := t.callbacks
	t.mu.RUnlock()

	for _, cb := range cbs {
		cb(record)
	}
}

// Run starts the tailer main loop.
func (t *Tailer) Run(ctx context.Context, stopCh chan struct{}) {
	// Initial file discovery
	t.discoverFiles()

	// Seek to end of existing files (only tail new content)
	for _, tf := range t.files {
		tf.file.Seek(0, io.SeekEnd)
		tf.offset, _ = tf.file.Seek(0, io.SeekCurrent)
		tf.reader = bufio.NewReader(tf.file)
	}

	// Watch directories for new files
	dirs := t.watchDirs()
	for _, dir := range dirs {
		t.watcher.Add(dir)
	}

	pollTicker := time.NewTicker(250 * time.Millisecond)
	defer pollTicker.Stop()

	rotateTicker := time.NewTicker(5 * time.Second)
	defer rotateTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return

		case event := <-t.watcher.Events:
			if event.Op&(fsnotify.Create|fsnotify.Write) != 0 {
				t.handleFileEvent(event.Name)
			}

		case <-pollTicker.C:
			t.readAllFiles()

		case <-rotateTicker.C:
			t.checkRotation()
			t.discoverFiles()

		case err := <-t.watcher.Errors:
			t.logger.Debug("watcher error", zap.Error(err))
		}
	}
}

// Stop cleans up the tailer.
func (t *Tailer) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.watcher.Close()
	for _, tf := range t.files {
		tf.file.Close()
	}
}

func (t *Tailer) discoverFiles() {
	matches, err := filepath.Glob(t.pattern)
	if err != nil {
		t.logger.Debug("glob error", zap.String("pattern", t.pattern), zap.Error(err))
		return
	}

	for _, path := range matches {
		if t.isExcluded(path) {
			continue
		}
		if _, ok := t.files[path]; ok {
			continue
		}

		t.openFile(path)
	}
}

func (t *Tailer) openFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		t.logger.Debug("open file error", zap.String("path", path), zap.Error(err))
		return
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return
	}

	tf := &tailedFile{
		path:   path,
		file:   f,
		offset: 0,
		reader: bufio.NewReader(f),
	}

	// Get inode for rotation detection
	tf.inode = fileInode(info)
	t.files[path] = tf

	t.logger.Debug("tailing file", zap.String("path", path))
}

func (t *Tailer) readAllFiles() {
	for _, tf := range t.files {
		t.readFile(tf)
	}
}

func (t *Tailer) readFile(tf *tailedFile) {
	for {
		line, err := tf.reader.ReadString('\n')
		if len(line) > 0 {
			// Remove trailing newline
			if line[len(line)-1] == '\n' {
				line = line[:len(line)-1]
			}
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}

			if line != "" {
				record := t.parser.Parse(line, t.format)
				record.Source = "file"
				record.FilePath = tf.path
				t.emit(record)
			}
		}

		if err != nil {
			break
		}
	}

	tf.offset, _ = tf.file.Seek(0, io.SeekCurrent)
}

func (t *Tailer) handleFileEvent(path string) {
	if t.isExcluded(path) {
		return
	}

	matched, _ := filepath.Match(t.pattern, path)
	if !matched {
		// Check if it's in a watched directory
		dir := filepath.Dir(path)
		patDir := filepath.Dir(t.pattern)
		if dir != patDir {
			return
		}
	}

	if _, ok := t.files[path]; !ok {
		t.openFile(path)
	}
}

func (t *Tailer) checkRotation() {
	for path, tf := range t.files {
		info, err := os.Stat(path)
		if err != nil {
			// File removed
			tf.file.Close()
			delete(t.files, path)
			continue
		}

		currentInode := fileInode(info)

		// Rotation detected: inode changed or file shrank
		if currentInode != tf.inode || info.Size() < tf.offset {
			t.logger.Debug("rotation detected", zap.String("path", path))
			// B2 fix: drain remaining data from old file before closing
			t.readFile(tf)
			tf.file.Close()
			delete(t.files, path)
			t.openFile(path)
		}
	}
}

func (t *Tailer) isExcluded(path string) bool {
	for _, excl := range t.excludes {
		if matched, _ := filepath.Match(excl, path); matched {
			return true
		}
		if matched, _ := filepath.Match(excl, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}

func (t *Tailer) watchDirs() []string {
	dir := filepath.Dir(t.pattern)
	if dir == "" {
		dir = "."
	}

	// Expand to real path
	abs, err := filepath.Abs(dir)
	if err != nil {
		return []string{dir}
	}
	return []string{abs}
}

// fileInode extracts the inode number from os.FileInfo (platform-specific).
func fileInode(info os.FileInfo) uint64 {
	return fileInodeImpl(info)
}
