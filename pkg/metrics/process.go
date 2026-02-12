// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package metrics

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
	"go.uber.org/zap"
)

// ProcessCollector gathers per-process metrics for observed PIDs.
// This is what Datadog (system.processes.*), Dynatrace (process.*),
// and New Relic (ProcessSample) collect for individual processes.
type ProcessCollector struct {
	logger *zap.Logger

	mu        sync.RWMutex
	callbacks []func(*Metric)
	pids      map[uint32]struct{} // PIDs to observe

	wg     sync.WaitGroup
	stopCh chan struct{}
}

// NewProcessCollector creates a new per-process metrics collector.
func NewProcessCollector(logger *zap.Logger) *ProcessCollector {
	return &ProcessCollector{
		logger: logger,
		pids:   make(map[uint32]struct{}),
		stopCh: make(chan struct{}),
	}
}

// OnMetric registers a callback for emitted metrics.
func (pc *ProcessCollector) OnMetric(fn func(*Metric)) {
	pc.mu.Lock()
	pc.callbacks = append(pc.callbacks, fn)
	pc.mu.Unlock()
}

func (pc *ProcessCollector) emit(m *Metric) {
	pc.mu.RLock()
	cbs := pc.callbacks
	pc.mu.RUnlock()
	for _, cb := range cbs {
		cb(m)
	}
}

// AddPID registers a PID for process-level metric collection.
func (pc *ProcessCollector) AddPID(pid uint32) {
	pc.mu.Lock()
	pc.pids[pid] = struct{}{}
	pc.mu.Unlock()
}

// RemovePID unregisters a PID from process-level metric collection.
func (pc *ProcessCollector) RemovePID(pid uint32) {
	pc.mu.Lock()
	delete(pc.pids, pid)
	pc.mu.Unlock()
}

// Start begins periodic per-process metric collection.
func (pc *ProcessCollector) Start(ctx context.Context, interval time.Duration) error {
	if interval == 0 {
		interval = 15 * time.Second
	}

	pc.wg.Add(1)
	go func() {
		defer pc.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				pc.collect()
			case <-pc.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	pc.logger.Info("process metrics collector started", zap.Duration("interval", interval))
	return nil
}

// Stop halts process metric collection.
func (pc *ProcessCollector) Stop() error {
	close(pc.stopCh)
	pc.wg.Wait()
	return nil
}

func (pc *ProcessCollector) collect() {
	now := time.Now()

	pc.mu.RLock()
	pids := make([]uint32, 0, len(pc.pids))
	for pid := range pc.pids {
		pids = append(pids, pid)
	}
	pc.mu.RUnlock()

	for _, pid := range pids {
		pc.collectPID(pid, now)
	}
}

func (pc *ProcessCollector) collectPID(pid uint32, now time.Time) {
	proc, err := process.NewProcess(int32(pid))
	if err != nil {
		// Process may have exited
		pc.RemovePID(pid)
		return
	}

	pidStr := fmt.Sprintf("%d", pid)
	name, _ := proc.Name()
	labels := map[string]string{
		"pid":          pidStr,
		"process_name": name,
	}

	// CPU percent
	cpuPct, err := proc.CPUPercent()
	if err == nil {
		pc.emit(&Metric{
			Name:      "process.cpu.utilization",
			Unit:      "%",
			Type:      Gauge,
			Value:     cpuPct,
			Timestamp: now,
			Labels:    labels,
		})
	}

	// Memory info: RSS, VMS
	memInfo, err := proc.MemoryInfo()
	if err == nil {
		pc.emit(&Metric{
			Name:      "process.memory.physical",
			Unit:      "By",
			Type:      Gauge,
			Value:     float64(memInfo.RSS),
			Timestamp: now,
			Labels:    labels,
		})
		pc.emit(&Metric{
			Name:      "process.memory.virtual",
			Unit:      "By",
			Type:      Gauge,
			Value:     float64(memInfo.VMS),
			Timestamp: now,
			Labels:    labels,
		})
	}

	// Memory percent
	memPct, err := proc.MemoryPercent()
	if err == nil {
		pc.emit(&Metric{
			Name:      "process.memory.utilization",
			Unit:      "%",
			Type:      Gauge,
			Value:     float64(memPct),
			Timestamp: now,
			Labels:    labels,
		})
	}

	// Thread count
	threads, err := proc.NumThreads()
	if err == nil {
		pc.emit(&Metric{
			Name:      "process.threads",
			Unit:      "{threads}",
			Type:      Gauge,
			Value:     float64(threads),
			Timestamp: now,
			Labels:    labels,
		})
	}

	// File descriptors (Linux)
	fds, err := proc.NumFDs()
	if err == nil {
		pc.emit(&Metric{
			Name:      "process.open_file_descriptors",
			Unit:      "{descriptors}",
			Type:      Gauge,
			Value:     float64(fds),
			Timestamp: now,
			Labels:    labels,
		})
	}

	// I/O counters
	ioCounters, err := proc.IOCounters()
	if err == nil {
		pc.emit(&Metric{
			Name:      "process.disk.io.read",
			Unit:      "By",
			Type:      Counter,
			Value:     float64(ioCounters.ReadBytes),
			Timestamp: now,
			Labels:    labels,
		})
		pc.emit(&Metric{
			Name:      "process.disk.io.write",
			Unit:      "By",
			Type:      Counter,
			Value:     float64(ioCounters.WriteBytes),
			Timestamp: now,
			Labels:    labels,
		})
		pc.emit(&Metric{
			Name:      "process.disk.operations.read",
			Unit:      "{operations}",
			Type:      Counter,
			Value:     float64(ioCounters.ReadCount),
			Timestamp: now,
			Labels:    labels,
		})
		pc.emit(&Metric{
			Name:      "process.disk.operations.write",
			Unit:      "{operations}",
			Type:      Counter,
			Value:     float64(ioCounters.WriteCount),
			Timestamp: now,
			Labels:    labels,
		})
	}

	// Context switches (voluntary + involuntary)
	ctxSwitches, err := proc.NumCtxSwitches()
	if err == nil {
		pc.emit(&Metric{
			Name:      "process.context_switches.voluntary",
			Unit:      "{switches}",
			Type:      Counter,
			Value:     float64(ctxSwitches.Voluntary),
			Timestamp: now,
			Labels:    labels,
		})
		pc.emit(&Metric{
			Name:      "process.context_switches.involuntary",
			Unit:      "{switches}",
			Type:      Counter,
			Value:     float64(ctxSwitches.Involuntary),
			Timestamp: now,
			Labels:    labels,
		})
	}
}
