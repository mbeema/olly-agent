// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package metrics

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	gopsutilDisk "github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

func (c *Collector) collectLoadAvg(now time.Time) {
	avg, err := load.Avg()
	if err != nil {
		c.logger.Debug("load average error")
		return
	}

	c.emit(&Metric{
		Name:        "system.cpu.load_average.1m",
		Description: "1-minute load average",
		Type:        Gauge,
		Value:       avg.Load1,
		Timestamp:   now,
	})
	c.emit(&Metric{
		Name:        "system.cpu.load_average.5m",
		Description: "5-minute load average",
		Type:        Gauge,
		Value:       avg.Load5,
		Timestamp:   now,
	})
	c.emit(&Metric{
		Name:        "system.cpu.load_average.15m",
		Description: "15-minute load average",
		Type:        Gauge,
		Value:       avg.Load15,
		Timestamp:   now,
	})

	// Normalized load (load / num_cpus) — what Datadog reports as system.load.norm.*
	numCPUs := float64(runtime.NumCPU())
	if numCPUs > 0 {
		c.emit(&Metric{
			Name:        "system.cpu.load_average.1m.normalized",
			Description: "1-minute load average per CPU",
			Type:        Gauge,
			Value:       avg.Load1 / numCPUs,
			Timestamp:   now,
		})
		c.emit(&Metric{
			Name:  "system.cpu.load_average.5m.normalized",
			Type:  Gauge,
			Value: avg.Load5 / numCPUs,
			Timestamp: now,
		})
		c.emit(&Metric{
			Name:  "system.cpu.load_average.15m.normalized",
			Type:  Gauge,
			Value: avg.Load15 / numCPUs,
			Timestamp: now,
		})
	}
}

func (c *Collector) collectFileDescriptors(now time.Time) {
	if runtime.GOOS != "linux" {
		return
	}

	data, err := os.ReadFile("/proc/sys/fs/file-nr")
	if err != nil {
		c.logger.Debug("file descriptors error")
		return
	}

	fields := strings.Fields(strings.TrimSpace(string(data)))
	if len(fields) < 3 {
		return
	}

	open, _ := strconv.ParseFloat(fields[0], 64)
	max, _ := strconv.ParseFloat(fields[2], 64)

	c.emit(&Metric{
		Name:        "system.filesystem.file_descriptors.open",
		Description: "Number of open file descriptors",
		Unit:        "{descriptors}",
		Type:        Gauge,
		Value:       open,
		Timestamp:   now,
	})
	c.emit(&Metric{
		Name:        "system.filesystem.file_descriptors.max",
		Description: "Maximum file descriptors allowed",
		Unit:        "{descriptors}",
		Type:        Gauge,
		Value:       max,
		Timestamp:   now,
	})
}

func (c *Collector) collectTCPStates(now time.Time) {
	conns, err := net.Connections("tcp")
	if err != nil {
		c.logger.Debug("tcp connections error")
		return
	}

	states := make(map[string]int)
	for _, conn := range conns {
		states[conn.Status]++
	}

	for state, count := range states {
		c.emit(&Metric{
			Name:        "system.network.tcp.connections",
			Description: "TCP connections by state",
			Unit:        "{connections}",
			Type:        Gauge,
			Value:       float64(count),
			Timestamp:   now,
			Labels:      map[string]string{"state": strings.ToLower(state)},
		})
	}
}

func (c *Collector) collectDiskIO(now time.Time) {
	counters, err := gopsutilDisk.IOCounters()
	if err != nil {
		c.logger.Debug("disk IO error")
		return
	}

	for device, stats := range counters {
		labels := map[string]string{"device": device}

		c.emit(&Metric{
			Name:      "system.disk.io.read",
			Unit:      "By",
			Type:      Counter,
			Value:     float64(stats.ReadBytes),
			Timestamp: now,
			Labels:    labels,
		})
		c.emit(&Metric{
			Name:      "system.disk.io.write",
			Unit:      "By",
			Type:      Counter,
			Value:     float64(stats.WriteBytes),
			Timestamp: now,
			Labels:    labels,
		})
		c.emit(&Metric{
			Name:      "system.disk.operations.read",
			Unit:      "{operations}",
			Type:      Counter,
			Value:     float64(stats.ReadCount),
			Timestamp: now,
			Labels:    labels,
		})
		c.emit(&Metric{
			Name:      "system.disk.operations.write",
			Unit:      "{operations}",
			Type:      Counter,
			Value:     float64(stats.WriteCount),
			Timestamp: now,
			Labels:    labels,
		})

		// Disk IO time (what Datadog/Dynatrace collect for latency analysis)
		c.emit(&Metric{
			Name:      "system.disk.io.time.read",
			Unit:      "ms",
			Type:      Counter,
			Value:     float64(stats.ReadTime),
			Timestamp: now,
			Labels:    labels,
		})
		c.emit(&Metric{
			Name:      "system.disk.io.time.write",
			Unit:      "ms",
			Type:      Counter,
			Value:     float64(stats.WriteTime),
			Timestamp: now,
			Labels:    labels,
		})
		c.emit(&Metric{
			Name:        "system.disk.io.time.io",
			Description: "Time spent doing I/O operations",
			Unit:        "ms",
			Type:        Counter,
			Value:       float64(stats.IoTime),
			Timestamp:   now,
			Labels:      labels,
		})
		c.emit(&Metric{
			Name:        "system.disk.io.weighted_time",
			Description: "Weighted time spent doing I/O",
			Unit:        "ms",
			Type:        Counter,
			Value:       float64(stats.WeightedIO),
			Timestamp:   now,
			Labels:      labels,
		})
		c.emit(&Metric{
			Name:      "system.disk.merged.read",
			Unit:      "{operations}",
			Type:      Counter,
			Value:     float64(stats.MergedReadCount),
			Timestamp: now,
			Labels:    labels,
		})
		c.emit(&Metric{
			Name:      "system.disk.merged.write",
			Unit:      "{operations}",
			Type:      Counter,
			Value:     float64(stats.MergedWriteCount),
			Timestamp: now,
			Labels:    labels,
		})
	}
}

func (c *Collector) collectUptime(now time.Time) {
	uptime, err := host.Uptime()
	if err != nil {
		c.logger.Debug("uptime error")
		return
	}

	c.emit(&Metric{
		Name:        "system.uptime",
		Description: "System uptime in seconds",
		Unit:        "s",
		Type:        Gauge,
		Value:       float64(uptime),
		Timestamp:   now,
	})
}

// collectSystemStats gathers context switches, interrupts, and process counts.
// These are collected by all major vendors (Datadog, Dynatrace, New Relic, Elastic).
func (c *Collector) collectSystemStats(now time.Time) {
	// Context switches and interrupts (from /proc/stat on Linux, host.Info fallback)
	misc, err := load.Misc()
	if err == nil {
		c.emit(&Metric{
			Name:        "system.cpu.context_switches",
			Description: "Total context switches",
			Unit:        "{switches}",
			Type:        Counter,
			Value:       float64(misc.Ctxt),
			Timestamp:   now,
		})
		c.emit(&Metric{
			Name:        "system.processes.running",
			Description: "Number of running processes",
			Unit:        "{processes}",
			Type:        Gauge,
			Value:       float64(misc.ProcsRunning),
			Timestamp:   now,
		})
		c.emit(&Metric{
			Name:        "system.processes.blocked",
			Description: "Number of blocked processes",
			Unit:        "{processes}",
			Type:        Gauge,
			Value:       float64(misc.ProcsBlocked),
			Timestamp:   now,
		})
		c.emit(&Metric{
			Name:        "system.processes.created",
			Description: "Total processes created since boot",
			Unit:        "{processes}",
			Type:        Counter,
			Value:       float64(misc.ProcsCreated),
			Timestamp:   now,
		})
	}

	// Total process count
	procs, err := process.Pids()
	if err == nil {
		c.emit(&Metric{
			Name:        "system.processes.count",
			Description: "Total number of processes",
			Unit:        "{processes}",
			Type:        Gauge,
			Value:       float64(len(procs)),
			Timestamp:   now,
		})
	}

	// CPU count (physical cores, for saturation analysis)
	physCores, err := cpu.Counts(false)
	if err == nil {
		c.emit(&Metric{
			Name:        "system.cpu.physical_cores",
			Description: "Number of physical CPU cores",
			Unit:        "{cores}",
			Type:        Gauge,
			Value:       float64(physCores),
			Timestamp:   now,
		})
	}
}
