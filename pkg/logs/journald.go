// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package logs

import (
	"bufio"
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// JournaldReader reads logs from systemd-journald via journalctl --follow.
type JournaldReader struct {
	units  []string
	logger *zap.Logger

	mu        sync.RWMutex
	callbacks []func(*LogRecord)

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewJournaldReader creates a reader that follows journald output.
// If units is non-empty, only those systemd units are followed.
func NewJournaldReader(units []string, logger *zap.Logger) *JournaldReader {
	return &JournaldReader{
		units:  units,
		logger: logger,
	}
}

// OnLog registers a callback for log records from journald.
func (j *JournaldReader) OnLog(fn func(*LogRecord)) {
	j.mu.Lock()
	j.callbacks = append(j.callbacks, fn)
	j.mu.Unlock()
}

func (j *JournaldReader) emit(record *LogRecord) {
	j.mu.RLock()
	cbs := j.callbacks
	j.mu.RUnlock()

	for _, cb := range cbs {
		cb(record)
	}
}

// Start begins reading from journald. It spawns journalctl as a subprocess
// and retries on exit after 5 seconds. If journalctl is not found, it logs
// a warning and returns without error.
func (j *JournaldReader) Start(ctx context.Context) error {
	if _, err := exec.LookPath("journalctl"); err != nil {
		j.logger.Warn("journalctl not found, skipping journald reader")
		return nil
	}

	ctx, cancel := context.WithCancel(ctx)
	j.cancel = cancel

	j.wg.Add(1)
	go j.run(ctx)
	return nil
}

func (j *JournaldReader) run(ctx context.Context) {
	defer j.wg.Done()

	for {
		if err := j.follow(ctx); err != nil && ctx.Err() == nil {
			j.logger.Warn("journalctl exited, retrying in 5s", zap.Error(err))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (j *JournaldReader) follow(ctx context.Context) error {
	args := []string{"--follow", "-o", "json", "--since", "now"}
	for _, unit := range j.units {
		args = append(args, "--unit="+unit)
	}

	cmd := exec.CommandContext(ctx, "journalctl", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	j.logger.Info("journald reader started",
		zap.Strings("units", j.units),
	)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 256*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if record := j.parseLine(line); record != nil {
			j.emit(record)
		}
	}

	return cmd.Wait()
}

func (j *JournaldReader) parseLine(line string) *LogRecord {
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(line), &data); err != nil {
		return nil
	}

	record := &LogRecord{
		Timestamp:  time.Now(),
		Source:     "journald",
		Attributes: make(map[string]interface{}),
	}

	// Parse timestamp: __REALTIME_TIMESTAMP is microseconds since epoch
	if tsStr, ok := data["__REALTIME_TIMESTAMP"].(string); ok {
		if usec, err := strconv.ParseInt(tsStr, 10, 64); err == nil {
			record.Timestamp = time.Unix(usec/1_000_000, (usec%1_000_000)*1000)
		}
	}

	// Message body
	if msg, ok := data["MESSAGE"].(string); ok {
		record.Body = msg
	}

	// Priority → level (syslog: 0=emerg..7=debug)
	if priStr, ok := data["PRIORITY"].(string); ok {
		if pri, err := strconv.Atoi(priStr); err == nil {
			record.Level = journaldPriorityToLevel(pri)
		}
	}

	// PID
	if pidStr, ok := data["_PID"].(string); ok {
		if pid, err := strconv.Atoi(pidStr); err == nil {
			record.PID = pid
		}
	}

	// Systemd unit
	unit := ""
	if u, ok := data["_SYSTEMD_UNIT"].(string); ok {
		unit = u
		record.Attributes["systemd.unit"] = u
	}

	// Syslog identifier (process name)
	if ident, ok := data["SYSLOG_IDENTIFIER"].(string); ok {
		record.ProcessName = ident
	}

	// Classify log type based on unit
	record.Attributes["log.type"] = classifyJournaldUnit(unit)

	return record
}

// classifyJournaldUnit maps a systemd unit name to a log type category.
func classifyJournaldUnit(unit string) string {
	lower := strings.ToLower(unit)
	switch {
	case strings.Contains(lower, "sshd") ||
		strings.Contains(lower, "sudo") ||
		strings.Contains(lower, "systemd-logind") ||
		strings.Contains(lower, "pam"):
		return "security"
	case strings.Contains(lower, "auditd") ||
		strings.Contains(lower, "audit"):
		return "audit"
	case strings.Contains(lower, "kernel") ||
		strings.Contains(lower, "systemd") ||
		strings.Contains(lower, "crond") ||
		strings.Contains(lower, "dnf") ||
		strings.Contains(lower, "yum"):
		return "system"
	default:
		return "application"
	}
}

// journaldPriorityToLevel maps syslog priority (0-7) to LogLevel.
func journaldPriorityToLevel(pri int) LogLevel {
	switch {
	case pri <= 2: // emerg, alert, crit
		return LevelFatal
	case pri == 3: // err
		return LevelError
	case pri == 4: // warning
		return LevelWarn
	case pri <= 6: // notice, info
		return LevelInfo
	default: // debug
		return LevelDebug
	}
}

// Stop halts the journald reader.
func (j *JournaldReader) Stop() {
	if j.cancel != nil {
		j.cancel()
	}
	j.wg.Wait()
}
