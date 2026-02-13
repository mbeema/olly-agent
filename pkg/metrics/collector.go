// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package metrics

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/mbeema/olly/pkg/config"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"go.uber.org/zap"
)

// Metric represents a single metric data point.
type Metric struct {
	Name        string
	Description string
	Unit        string
	Type        MetricType
	Value       float64
	Timestamp   time.Time
	StartTime   time.Time         // Start time for cumulative counters/histograms (OTLP StartTimeUnixNano)
	Labels      map[string]string
	Histogram   *HistogramData // populated for Histogram type
	ServiceName string         // Service that produced this metric
}

// HistogramData holds histogram bucket data for export.
type HistogramData struct {
	Count   uint64
	Sum     float64
	Buckets []HistogramBucket
}

// HistogramBucket is a single histogram bucket.
type HistogramBucket struct {
	UpperBound float64
	Count      uint64 // cumulative count of values <= UpperBound
}

// MetricType identifies the kind of metric.
type MetricType int

const (
	Gauge MetricType = iota
	Counter
	Histogram
)

// Collector gathers host and process metrics.
type Collector struct {
	cfg       *config.MetricsConfig
	logger    *zap.Logger
	startTime time.Time // OTLP StartTimeUnixNano for cumulative metrics

	mu        sync.RWMutex
	callbacks []func(*Metric)

	wg       sync.WaitGroup
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewCollector creates a new metrics collector.
func NewCollector(cfg *config.MetricsConfig, logger *zap.Logger) *Collector {
	return &Collector{
		cfg:       cfg,
		logger:    logger,
		startTime: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

// OnMetric registers a callback for emitted metrics.
func (c *Collector) OnMetric(fn func(*Metric)) {
	c.mu.Lock()
	c.callbacks = append(c.callbacks, fn)
	c.mu.Unlock()
}

func (c *Collector) emit(m *Metric) {
	c.mu.RLock()
	cbs := c.callbacks
	c.mu.RUnlock()

	for _, cb := range cbs {
		cb(m)
	}
}

// Start begins periodic metric collection.
func (c *Collector) Start(ctx context.Context) error {
	interval := c.cfg.Interval
	if interval == 0 {
		interval = 15 * time.Second
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Collect once immediately
		c.collect()

		for {
			select {
			case <-ticker.C:
				c.collect()
			case <-c.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	c.logger.Info("metrics collector started", zap.Duration("interval", interval))
	return nil
}

// Stop halts metric collection.
func (c *Collector) Stop() error {
	c.stopOnce.Do(func() { close(c.stopCh) })
	c.wg.Wait()
	return nil
}

func (c *Collector) collect() {
	now := time.Now()

	if c.cfg.Host.Enabled {
		c.collectCPU(now)
		c.collectMemory(now)
		c.collectDisk(now)
		c.collectNetwork(now)
		c.collectLoadAvg(now)
		c.collectFileDescriptors(now)
		c.collectTCPStates(now)
		c.collectDiskIO(now)
		c.collectUptime(now)
		c.collectSystemStats(now)
	}

	if c.cfg.Process.Enabled {
		c.collectProcess(now)
	}
}

func (c *Collector) collectCPU(now time.Time) {
	percentages, err := cpu.Percent(0, false)
	if err != nil {
		c.logger.Debug("cpu metrics error", zap.Error(err))
		return
	}

	if len(percentages) > 0 {
		c.emit(&Metric{
			Name:        "system.cpu.utilization",
			Description: "CPU utilization as a ratio (0-1)",
			Unit:        "1",
			Type:        Gauge,
			Value:       percentages[0] / 100,
			Timestamp:   now,
			Labels:      map[string]string{"cpu": "total"},
		})
	}

	// Per-CPU
	perCPU, err := cpu.Percent(0, true)
	if err == nil {
		for i, pct := range perCPU {
			c.emit(&Metric{
				Name:      "system.cpu.utilization",
				Unit:      "1",
				Type:      Gauge,
				Value:     pct / 100,
				Timestamp: now,
				Labels:    map[string]string{"cpu": fmt.Sprintf("cpu%d", i)},
			})
		}
	}

	// CPU time breakdown by mode (OTEL semconv: system.cpu.time, unit=s, Counter)
	times, err := cpu.Times(false)
	if err == nil && len(times) > 0 {
		t := times[0]
		modes := map[string]float64{
			"user":    t.User,
			"system":  t.System,
			"idle":    t.Idle,
			"nice":    t.Nice,
			"iowait":  t.Iowait,
			"irq":     t.Irq,
			"softirq": t.Softirq,
			"steal":   t.Steal,
		}
		for mode, seconds := range modes {
			c.emit(&Metric{
				Name:      "system.cpu.time",
				Unit:      "s",
				Type:      Counter,
				Value:     seconds,
				Timestamp: now,
				StartTime: c.startTime,
				Labels:    map[string]string{"cpu.mode": mode},
			})
		}
	}

	// CPU count (logical)
	logicalCPUs := runtime.NumCPU()
	c.emit(&Metric{
		Name:        "system.cpu.count",
		Description: "Number of logical CPUs",
		Unit:        "{cpus}",
		Type:        Gauge,
		Value:       float64(logicalCPUs),
		Timestamp:   now,
	})
}

func (c *Collector) collectMemory(now time.Time) {
	v, err := mem.VirtualMemory()
	if err != nil {
		c.logger.Debug("memory metrics error", zap.Error(err))
		return
	}

	// Breakdown by state (OTEL semconv: system.memory.usage, attr system.memory.state)
	memStates := map[string]float64{
		"used":      float64(v.Used),
		"free":      float64(v.Free),
		"available": float64(v.Available),
		"cached":    float64(v.Cached),
		"buffered":  float64(v.Buffers),
		"shared":    float64(v.Shared),
		"slab":      float64(v.Slab),
	}
	for state, val := range memStates {
		c.emit(&Metric{
			Name:      "system.memory.usage",
			Unit:      "By",
			Type:      Gauge,
			Value:     val,
			Timestamp: now,
			Labels:    map[string]string{"system.memory.state": state},
		})
	}

	c.emit(&Metric{
		Name:        "system.memory.limit",
		Description: "Total physical memory",
		Unit:        "By",
		Type:        Gauge,
		Value:       float64(v.Total),
		Timestamp:   now,
	})

	c.emit(&Metric{
		Name:        "system.memory.utilization",
		Description: "Memory utilization as a ratio (0-1)",
		Unit:        "1",
		Type:        Gauge,
		Value:       v.UsedPercent / 100,
		Timestamp:   now,
	})

	// Paging metrics (OTEL semconv: system.paging.*)
	swap, err := mem.SwapMemory()
	if err == nil {
		c.emit(&Metric{
			Name:      "system.paging.usage",
			Unit:      "By",
			Type:      Gauge,
			Value:     float64(swap.Used),
			Timestamp: now,
			Labels:    map[string]string{"system.paging.state": "used"},
		})
		c.emit(&Metric{
			Name:      "system.paging.usage",
			Unit:      "By",
			Type:      Gauge,
			Value:     float64(swap.Free),
			Timestamp: now,
			Labels:    map[string]string{"system.paging.state": "free"},
		})
		c.emit(&Metric{
			Name:        "system.paging.limit",
			Description: "Total swap space",
			Unit:        "By",
			Type:        Gauge,
			Value:       float64(swap.Total),
			Timestamp:   now,
		})
		if swap.Total > 0 {
			c.emit(&Metric{
				Name:      "system.paging.utilization",
				Unit:      "1",
				Type:      Gauge,
				Value:     swap.UsedPercent / 100,
				Timestamp: now,
			})
		}
	}
}

func (c *Collector) collectDisk(now time.Time) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		c.logger.Debug("disk metrics error", zap.Error(err))
		return
	}

	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}

		labels := map[string]string{
			"device":     p.Device,
			"mountpoint": p.Mountpoint,
			"fstype":     p.Fstype,
		}

		c.emit(&Metric{
			Name:      "system.disk.usage",
			Unit:      "By",
			Type:      Gauge,
			Value:     float64(usage.Used),
			Timestamp: now,
			Labels:    labels,
		})

		c.emit(&Metric{
			Name:      "system.disk.utilization",
			Unit:      "1",
			Type:      Gauge,
			Value:     usage.UsedPercent / 100,
			Timestamp: now,
			Labels:    labels,
		})

		c.emit(&Metric{
			Name:      "system.disk.total",
			Unit:      "By",
			Type:      Gauge,
			Value:     float64(usage.Total),
			Timestamp: now,
			Labels:    labels,
		})

		c.emit(&Metric{
			Name:      "system.disk.free",
			Unit:      "By",
			Type:      Gauge,
			Value:     float64(usage.Free),
			Timestamp: now,
			Labels:    labels,
		})

		// Inode metrics (what Datadog/Elastic collect)
		if usage.InodesTotal > 0 {
			c.emit(&Metric{
				Name:      "system.filesystem.inodes.total",
				Unit:      "{inodes}",
				Type:      Gauge,
				Value:     float64(usage.InodesTotal),
				Timestamp: now,
				Labels:    labels,
			})
			c.emit(&Metric{
				Name:      "system.filesystem.inodes.used",
				Unit:      "{inodes}",
				Type:      Gauge,
				Value:     float64(usage.InodesUsed),
				Timestamp: now,
				Labels:    labels,
			})
			c.emit(&Metric{
				Name:      "system.filesystem.inodes.free",
				Unit:      "{inodes}",
				Type:      Gauge,
				Value:     float64(usage.InodesFree),
				Timestamp: now,
				Labels:    labels,
			})
			c.emit(&Metric{
				Name:      "system.filesystem.inodes.utilization",
				Unit:      "1",
				Type:      Gauge,
				Value:     usage.InodesUsedPercent / 100,
				Timestamp: now,
				Labels:    labels,
			})
		}
	}
}

func (c *Collector) collectNetwork(now time.Time) {
	counters, err := net.IOCounters(true)
	if err != nil {
		c.logger.Debug("network metrics error", zap.Error(err))
		return
	}

	for _, iface := range counters {
		labels := map[string]string{"network.interface.name": iface.Name}

		c.emit(&Metric{
			Name:      "system.network.io",
			Unit:      "By",
			Type:      Counter,
			Value:     float64(iface.BytesSent),
			Timestamp: now,
			StartTime: c.startTime,
			Labels:    mergeMaps(labels, map[string]string{"network.io.direction": "transmit"}),
		})

		c.emit(&Metric{
			Name:      "system.network.io",
			Unit:      "By",
			Type:      Counter,
			Value:     float64(iface.BytesRecv),
			Timestamp: now,
			StartTime: c.startTime,
			Labels:    mergeMaps(labels, map[string]string{"network.io.direction": "receive"}),
		})

		c.emit(&Metric{
			Name:      "system.network.packet.count",
			Unit:      "{packets}",
			Type:      Counter,
			Value:     float64(iface.PacketsSent),
			Timestamp: now,
			StartTime: c.startTime,
			Labels:    mergeMaps(labels, map[string]string{"network.io.direction": "transmit"}),
		})

		c.emit(&Metric{
			Name:      "system.network.packet.count",
			Unit:      "{packets}",
			Type:      Counter,
			Value:     float64(iface.PacketsRecv),
			Timestamp: now,
			StartTime: c.startTime,
			Labels:    mergeMaps(labels, map[string]string{"network.io.direction": "receive"}),
		})

		c.emit(&Metric{
			Name:      "system.network.errors",
			Unit:      "{errors}",
			Type:      Counter,
			Value:     float64(iface.Errout),
			Timestamp: now,
			StartTime: c.startTime,
			Labels:    mergeMaps(labels, map[string]string{"network.io.direction": "transmit"}),
		})

		c.emit(&Metric{
			Name:      "system.network.errors",
			Unit:      "{errors}",
			Type:      Counter,
			Value:     float64(iface.Errin),
			Timestamp: now,
			StartTime: c.startTime,
			Labels:    mergeMaps(labels, map[string]string{"network.io.direction": "receive"}),
		})

		c.emit(&Metric{
			Name:      "system.network.packet.dropped",
			Unit:      "{packets}",
			Type:      Counter,
			Value:     float64(iface.Dropout),
			Timestamp: now,
			StartTime: c.startTime,
			Labels:    mergeMaps(labels, map[string]string{"network.io.direction": "transmit"}),
		})

		c.emit(&Metric{
			Name:      "system.network.packet.dropped",
			Unit:      "{packets}",
			Type:      Counter,
			Value:     float64(iface.Dropin),
			Timestamp: now,
			StartTime: c.startTime,
			Labels:    mergeMaps(labels, map[string]string{"network.io.direction": "receive"}),
		})
	}
}

func (c *Collector) collectProcess(now time.Time) {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	c.emit(&Metric{
		Name:        "process.runtime.go.mem.heap_alloc",
		Description: "Heap allocation in bytes",
		Unit:        "By",
		Type:        Gauge,
		Value:       float64(memStats.HeapAlloc),
		Timestamp:   now,
	})

	c.emit(&Metric{
		Name:      "process.runtime.go.mem.heap_sys",
		Unit:      "By",
		Type:      Gauge,
		Value:     float64(memStats.HeapSys),
		Timestamp: now,
	})

	c.emit(&Metric{
		Name:        "process.runtime.go.goroutines",
		Description: "Number of goroutines",
		Unit:        "{goroutines}",
		Type:        Gauge,
		Value:       float64(runtime.NumGoroutine()),
		Timestamp:   now,
	})

	c.emit(&Metric{
		Name:      "process.runtime.go.gc.count",
		Unit:      "{collections}",
		Type:      Counter,
		Value:     float64(memStats.NumGC),
		Timestamp: now,
	})
}

func mergeMaps(a, b map[string]string) map[string]string {
	m := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		m[k] = v
	}
	for k, v := range b {
		m[k] = v
	}
	return m
}
