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
	Labels      map[string]string
	Histogram   *HistogramData // populated for Histogram type
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
	cfg    *config.MetricsConfig
	logger *zap.Logger

	mu        sync.RWMutex
	callbacks []func(*Metric)

	wg     sync.WaitGroup
	stopCh chan struct{}
}

// NewCollector creates a new metrics collector.
func NewCollector(cfg *config.MetricsConfig, logger *zap.Logger) *Collector {
	return &Collector{
		cfg:    cfg,
		logger: logger,
		stopCh: make(chan struct{}),
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
	close(c.stopCh)
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
			Description: "CPU utilization as a percentage",
			Unit:        "%",
			Type:        Gauge,
			Value:       percentages[0],
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
				Unit:      "%",
				Type:      Gauge,
				Value:     pct,
				Timestamp: now,
				Labels:    map[string]string{"cpu": fmt.Sprintf("cpu%d", i)},
			})
		}
	}
}

func (c *Collector) collectMemory(now time.Time) {
	v, err := mem.VirtualMemory()
	if err != nil {
		c.logger.Debug("memory metrics error", zap.Error(err))
		return
	}

	c.emit(&Metric{
		Name:        "system.memory.usage",
		Description: "Memory usage in bytes",
		Unit:        "By",
		Type:        Gauge,
		Value:       float64(v.Used),
		Timestamp:   now,
		Labels:      map[string]string{"state": "used"},
	})

	c.emit(&Metric{
		Name:      "system.memory.usage",
		Unit:      "By",
		Type:      Gauge,
		Value:     float64(v.Available),
		Timestamp: now,
		Labels:    map[string]string{"state": "available"},
	})

	c.emit(&Metric{
		Name:        "system.memory.utilization",
		Description: "Memory utilization as a percentage",
		Unit:        "%",
		Type:        Gauge,
		Value:       v.UsedPercent,
		Timestamp:   now,
	})
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
			Unit:      "%",
			Type:      Gauge,
			Value:     usage.UsedPercent,
			Timestamp: now,
			Labels:    labels,
		})
	}
}

func (c *Collector) collectNetwork(now time.Time) {
	counters, err := net.IOCounters(true)
	if err != nil {
		c.logger.Debug("network metrics error", zap.Error(err))
		return
	}

	for _, iface := range counters {
		labels := map[string]string{"interface": iface.Name}

		c.emit(&Metric{
			Name:      "system.network.io",
			Unit:      "By",
			Type:      Counter,
			Value:     float64(iface.BytesSent),
			Timestamp: now,
			Labels:    mergeMaps(labels, map[string]string{"direction": "transmit"}),
		})

		c.emit(&Metric{
			Name:      "system.network.io",
			Unit:      "By",
			Type:      Counter,
			Value:     float64(iface.BytesRecv),
			Timestamp: now,
			Labels:    mergeMaps(labels, map[string]string{"direction": "receive"}),
		})

		c.emit(&Metric{
			Name:      "system.network.packets",
			Unit:      "{packets}",
			Type:      Counter,
			Value:     float64(iface.PacketsSent),
			Timestamp: now,
			Labels:    mergeMaps(labels, map[string]string{"direction": "transmit"}),
		})

		c.emit(&Metric{
			Name:      "system.network.packets",
			Unit:      "{packets}",
			Type:      Counter,
			Value:     float64(iface.PacketsRecv),
			Timestamp: now,
			Labels:    mergeMaps(labels, map[string]string{"direction": "receive"}),
		})

		c.emit(&Metric{
			Name:      "system.network.errors",
			Unit:      "{errors}",
			Type:      Counter,
			Value:     float64(iface.Errout),
			Timestamp: now,
			Labels:    mergeMaps(labels, map[string]string{"direction": "transmit"}),
		})

		c.emit(&Metric{
			Name:      "system.network.errors",
			Unit:      "{errors}",
			Type:      Counter,
			Value:     float64(iface.Errin),
			Timestamp: now,
			Labels:    mergeMaps(labels, map[string]string{"direction": "receive"}),
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
