// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package metrics

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ContainerCollector gathers cgroup v2 metrics when running inside a container.
// This covers what Datadog (docker.*), Dynatrace (container.*), and
// New Relic (ContainerSample) collect for container-level resource usage.
// Reads directly from cgroupfs — zero overhead, no Docker socket needed.
type ContainerCollector struct {
	logger    *zap.Logger
	cgroupDir string // auto-detected cgroup v2 mount path
	startTime time.Time // B6 fix: OTLP StartTimeUnixNano for cumulative counters

	mu        sync.RWMutex
	callbacks []func(*Metric)

	wg       sync.WaitGroup
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewContainerCollector creates a container metrics collector.
// Returns nil if not running inside a cgroup v2 environment.
func NewContainerCollector(logger *zap.Logger) *ContainerCollector {
	cgroupDir := detectCgroupDir()
	if cgroupDir == "" {
		logger.Debug("not running in cgroup v2 environment, container metrics disabled")
		return nil
	}

	return &ContainerCollector{
		logger:    logger,
		cgroupDir: cgroupDir,
		startTime: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

// OnMetric registers a callback for emitted metrics.
func (cc *ContainerCollector) OnMetric(fn func(*Metric)) {
	cc.mu.Lock()
	cc.callbacks = append(cc.callbacks, fn)
	cc.mu.Unlock()
}

func (cc *ContainerCollector) emit(m *Metric) {
	cc.mu.RLock()
	cbs := cc.callbacks
	cc.mu.RUnlock()
	for _, cb := range cbs {
		cb(m)
	}
}

// Start begins periodic container metric collection.
func (cc *ContainerCollector) Start(ctx context.Context, interval time.Duration) error {
	if interval == 0 {
		interval = 15 * time.Second
	}

	cc.wg.Add(1)
	go func() {
		defer cc.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		cc.collect()

		for {
			select {
			case <-ticker.C:
				cc.collect()
			case <-cc.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	cc.logger.Info("container metrics collector started",
		zap.String("cgroup_dir", cc.cgroupDir),
		zap.Duration("interval", interval),
	)
	return nil
}

// Stop halts container metric collection.
func (cc *ContainerCollector) Stop() error {
	cc.stopOnce.Do(func() { close(cc.stopCh) })
	cc.wg.Wait()
	return nil
}

func (cc *ContainerCollector) collect() {
	now := time.Now()
	cc.collectCPU(now)
	cc.collectMemory(now)
	cc.collectIO(now)
}

func (cc *ContainerCollector) collectCPU(now time.Time) {
	// cpu.stat: usage_usec, user_usec, system_usec, nr_periods, nr_throttled, throttled_usec
	data := cc.readCgroupFile("cpu.stat")
	if data == "" {
		return
	}

	stats := parseCgroupKV(data)
	// B6 fix: all counters include StartTime for OTLP cumulative semantics
	if v, ok := stats["usage_usec"]; ok {
		cc.emit(&Metric{
			Name:      "container.cpu.usage",
			Unit:      "us",
			Type:      Counter,
			Value:     float64(v),
			Timestamp: now,
			StartTime: cc.startTime,
		})
	}
	if v, ok := stats["user_usec"]; ok {
		cc.emit(&Metric{
			Name:      "container.cpu.usage.user",
			Unit:      "us",
			Type:      Counter,
			Value:     float64(v),
			Timestamp: now,
			StartTime: cc.startTime,
		})
	}
	if v, ok := stats["system_usec"]; ok {
		cc.emit(&Metric{
			Name:      "container.cpu.usage.system",
			Unit:      "us",
			Type:      Counter,
			Value:     float64(v),
			Timestamp: now,
			StartTime: cc.startTime,
		})
	}
	if v, ok := stats["nr_throttled"]; ok {
		cc.emit(&Metric{
			Name:      "container.cpu.throttled.count",
			Unit:      "{periods}",
			Type:      Counter,
			Value:     float64(v),
			Timestamp: now,
			StartTime: cc.startTime,
		})
	}
	if v, ok := stats["throttled_usec"]; ok {
		cc.emit(&Metric{
			Name:      "container.cpu.throttled.time",
			Unit:      "us",
			Type:      Counter,
			Value:     float64(v),
			Timestamp: now,
			StartTime: cc.startTime,
		})
	}

	// cpu.max: quota period (e.g. "100000 100000")
	maxData := cc.readCgroupFile("cpu.max")
	if maxData != "" {
		fields := strings.Fields(maxData)
		if len(fields) == 2 && fields[0] != "max" {
			quota, _ := strconv.ParseFloat(fields[0], 64)
			period, _ := strconv.ParseFloat(fields[1], 64)
			if period > 0 {
				cc.emit(&Metric{
					Name:        "container.cpu.limit",
					Description: "CPU limit in cores",
					Unit:        "{cores}",
					Type:        Gauge,
					Value:       quota / period,
					Timestamp:   now,
				})
			}
		}
	}
}

func (cc *ContainerCollector) collectMemory(now time.Time) {
	// memory.current: total memory usage in bytes
	current := cc.readCgroupUint("memory.current")
	if current >= 0 {
		cc.emit(&Metric{
			Name:      "container.memory.usage",
			Unit:      "By",
			Type:      Gauge,
			Value:     float64(current),
			Timestamp: now,
		})
	}

	// memory.max: memory limit
	maxMem := cc.readCgroupFile("memory.max")
	if maxMem != "" && strings.TrimSpace(maxMem) != "max" {
		v, err := strconv.ParseUint(strings.TrimSpace(maxMem), 10, 64)
		if err == nil {
			cc.emit(&Metric{
				Name:      "container.memory.limit",
				Unit:      "By",
				Type:      Gauge,
				Value:     float64(v),
				Timestamp: now,
			})
			// B7 fix: OTEL semconv uses 0-1 ratio, not 0-100 percentage
			if current >= 0 && v > 0 {
				cc.emit(&Metric{
					Name:      "container.memory.utilization",
					Unit:      "1",
					Type:      Gauge,
					Value:     float64(current) / float64(v),
					Timestamp: now,
				})
			}
		}
	}

	// memory.stat: detailed breakdown
	data := cc.readCgroupFile("memory.stat")
	if data == "" {
		return
	}

	stats := parseCgroupKV(data)
	memFields := map[string]string{
		"anon":         "container.memory.rss",
		"file":         "container.memory.cache",
		"kernel":       "container.memory.kernel",
		"sock":         "container.memory.sock",
		"slab":         "container.memory.slab",
		"pgfault":      "container.memory.pgfault",
		"pgmajfault":   "container.memory.pgmajfault",
		"oom_kill":     "container.memory.oom_kill",
	}
	for cgroupKey, metricName := range memFields {
		if v, ok := stats[cgroupKey]; ok {
			unit := "By"
			mtype := Gauge
			if cgroupKey == "pgfault" || cgroupKey == "pgmajfault" || cgroupKey == "oom_kill" {
				unit = "{events}"
				mtype = Counter
			}
			m := &Metric{
				Name:      metricName,
				Unit:      unit,
				Type:      MetricType(mtype),
				Value:     float64(v),
				Timestamp: now,
			}
			if mtype == Counter {
				m.StartTime = cc.startTime
			}
			cc.emit(m)
		}
	}
}

func (cc *ContainerCollector) collectIO(now time.Time) {
	// io.stat: per-device I/O statistics
	data := cc.readCgroupFile("io.stat")
	if data == "" {
		return
	}

	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		device := fields[0] // major:minor
		labels := map[string]string{"device": device}

		for _, kv := range fields[1:] {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			val, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				continue
			}

			var name, unit string
			switch parts[0] {
			case "rbytes":
				name = "container.disk.io.read"
				unit = "By"
			case "wbytes":
				name = "container.disk.io.write"
				unit = "By"
			case "rios":
				name = "container.disk.operations.read"
				unit = "{operations}"
			case "wios":
				name = "container.disk.operations.write"
				unit = "{operations}"
			default:
				continue
			}

			cc.emit(&Metric{
				Name:      name,
				Unit:      unit,
				Type:      Counter,
				Value:     float64(val),
				Timestamp: now,
				StartTime: cc.startTime,
				Labels:    labels,
			})
		}
	}
}

// Helper methods

func (cc *ContainerCollector) readCgroupFile(name string) string {
	data, err := os.ReadFile(filepath.Join(cc.cgroupDir, name))
	if err != nil {
		return ""
	}
	return string(data)
}

func (cc *ContainerCollector) readCgroupUint(name string) int64 {
	data := cc.readCgroupFile(name)
	if data == "" {
		return -1
	}
	v, err := strconv.ParseInt(strings.TrimSpace(data), 10, 64)
	if err != nil {
		return -1
	}
	return v
}

// detectCgroupDir finds the cgroup v2 directory for the current process.
func detectCgroupDir() string {
	// Check if unified cgroup v2 is mounted
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}

	for _, line := range strings.Split(string(data), "\n") {
		// cgroup v2: "0::/path"
		parts := strings.SplitN(line, ":", 3)
		if len(parts) == 3 && parts[0] == "0" && parts[1] == "" {
			cgroupPath := strings.TrimSpace(parts[2])
			dir := filepath.Join("/sys/fs/cgroup", cgroupPath)
			if _, err := os.Stat(filepath.Join(dir, "memory.current")); err == nil {
				return dir
			}
		}
	}

	return ""
}

// parseCgroupKV parses "key value\n" format used by cgroup stat files.
func parseCgroupKV(data string) map[string]uint64 {
	result := make(map[string]uint64)
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		result[fields[0]] = v
	}
	return result
}
