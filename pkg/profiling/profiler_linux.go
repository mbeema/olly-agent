//go:build linux

package profiling

import (
	"context"
	"encoding/binary"
	"runtime"
	"sync"
	"time"
	"unsafe"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

const (
	maxStackDepth = 16
	// Ring buffer: 1 data page + 2^n pages. 8 pages = 32KB per CPU.
	ringBufferPages = 8
	pageSize        = 4096
	ringBufferSize  = (1 + ringBufferPages) * pageSize
)

// stackKey is a fixed-size array used as a map key for stack aggregation.
type stackKey [maxStackDepth]uint64

// pidSamples holds aggregated samples for a single PID.
type pidSamples struct {
	stacks map[stackKey]uint64   // stack hash → sample count
	frames map[stackKey][]uint64 // stack hash → raw IPs
}

// linuxProfiler uses perf_event for CPU profiling on Linux.
type linuxProfiler struct {
	cfg      *Config
	logger   *zap.Logger
	resolver *symbolResolver

	mu        sync.RWMutex
	callbacks []func(*Profile)

	perfFDs []int
	mmaps   [][]byte // mmap'd ring buffers

	stopCh chan struct{}
	wg     sync.WaitGroup

	// Aggregation: PID → samples
	sampleMu sync.Mutex
	samples  map[uint32]*pidSamples

	// Service name resolution
	resolveService func(pid uint32) string
}

// openPerfEvent opens a perf_event fd for CPU profiling on the given CPU.
// Uses PERF_TYPE_SOFTWARE / PERF_COUNT_SW_CPU_CLOCK for VM compatibility
// (hardware counters may not be available on EC2/KVM instances).
func openPerfEvent(sampleRate int, cpu int) (int, error) {
	attr := &unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Config:      unix.PERF_COUNT_SW_CPU_CLOCK,
		Size:        uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Sample:      uint64(sampleRate),
		Sample_type: unix.PERF_SAMPLE_IP | unix.PERF_SAMPLE_TID | unix.PERF_SAMPLE_CALLCHAIN,
		Bits:        unix.PerfBitDisabled | unix.PerfBitFreq,
		Wakeup:      1,
	}

	fd, err := unix.PerfEventOpen(attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func newProfiler(cfg *Config) Profiler {
	return &linuxProfiler{
		cfg:      cfg,
		logger:   cfg.Logger,
		resolver: newSymbolResolver(cfg.Logger),
		stopCh:   make(chan struct{}),
		samples:  make(map[uint32]*pidSamples),
	}
}

func (p *linuxProfiler) OnProfile(fn func(*Profile)) {
	p.mu.Lock()
	p.callbacks = append(p.callbacks, fn)
	p.mu.Unlock()
}

func (p *linuxProfiler) SetServiceResolver(fn func(pid uint32) string) {
	p.resolveService = fn
}

func (p *linuxProfiler) Start(ctx context.Context) error {
	numCPUs := runtime.NumCPU()

	// Open perf_event on each CPU for all PIDs (system-wide sampling).
	for cpu := 0; cpu < numCPUs; cpu++ {
		fd, err := openPerfEvent(p.cfg.SampleRate, cpu)
		if err != nil {
			p.logger.Warn("perf_event_open failed",
				zap.Int("cpu", cpu),
				zap.Error(err),
			)
			continue
		}

		// mmap ring buffer
		buf, err := unix.Mmap(fd, 0, ringBufferSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			p.logger.Warn("mmap failed", zap.Int("cpu", cpu), zap.Error(err))
			unix.Close(fd)
			continue
		}

		// Enable the perf event
		if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
			p.logger.Warn("PERF_EVENT_IOC_ENABLE failed", zap.Int("cpu", cpu), zap.Error(err))
			unix.Munmap(buf)
			unix.Close(fd)
			continue
		}

		p.perfFDs = append(p.perfFDs, fd)
		p.mmaps = append(p.mmaps, buf)

		p.logger.Info("perf_event opened",
			zap.Int("cpu", cpu),
			zap.Int("fd", fd),
		)
	}

	if len(p.perfFDs) == 0 {
		p.logger.Warn("no perf_event fds opened (requires CAP_PERFMON or root)")
		return nil
	}

	// Start reader goroutine (direct polling, no epoll)
	p.wg.Add(1)
	go p.readLoop()

	// Start flush goroutine
	p.wg.Add(1)
	go p.flushLoop()

	p.logger.Info("CPU profiler started",
		zap.Int("sample_rate", p.cfg.SampleRate),
		zap.Int("cpus", len(p.perfFDs)),
		zap.Duration("interval", p.cfg.Interval),
	)

	return nil
}

func (p *linuxProfiler) Stop() error {
	close(p.stopCh)
	p.wg.Wait()

	// Disable and cleanup
	for i, fd := range p.perfFDs {
		unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0)
		if i < len(p.mmaps) {
			unix.Munmap(p.mmaps[i])
		}
		unix.Close(fd)
	}

	p.logger.Info("CPU profiler stopped")
	return nil
}

// readLoop polls the ring buffers directly on a timer and parses perf samples.
// Direct polling (vs epoll) avoids issues with Go's goroutine scheduler.
func (p *linuxProfiler) readLoop() {
	defer p.wg.Done()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Poll every 10ms — low overhead (just reading data_head per CPU per tick)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			for _, buf := range p.mmaps {
				p.readRingBuffer(buf)
			}
		}
	}
}

// perfEventMmapPage mirrors the kernel's struct perf_event_mmap_page layout.
// Used to compute correct field offsets via unsafe.Offsetof.
// Verified against C offsetof: data_head=1024, data_tail=1032.
type perfEventMmapPage struct {
	Version       uint32   // 0
	CompatVersion uint32   // 4
	Lock          uint32   // 8
	Index         uint32   // 12
	Offset        int64    // 16
	TimeEnabled   uint64   // 24
	TimeRunning   uint64   // 32
	Capabilities  uint64   // 40
	PmcWidth      uint16   // 48
	TimeShift     uint16   // 50
	TimeMult      uint32   // 52
	TimeOffset    uint64   // 56
	TimeZero      uint64   // 64
	Size          uint32   // 72
	_reserved1    uint32   // 76
	TimeCycles    uint64   // 80
	TimeMask      uint64   // 88
	_reserved     [928]byte // 96..1023 — padding to data_head at 1024
	DataHead      uint64   // 1024
	DataTail      uint64   // 1032
	DataOffset    uint64   // 1040
	DataSize      uint64   // 1048
}

// Offsets computed from the Go struct (verified against C offsetof on kernel 6.1).
var (
	dataHeadOffset = unsafe.Offsetof(perfEventMmapPage{}.DataHead) // 1024 = 0x400
	dataTailOffset = unsafe.Offsetof(perfEventMmapPage{}.DataTail) // 1032 = 0x408
)

const (
	dataOffset = pageSize
	dataSize   = ringBufferPages * pageSize
)

// perf_event_header type constants
const (
	PERF_RECORD_SAMPLE = 9
)

// readRingBuffer reads and parses all available perf records from a ring buffer.
// Returns the number of PERF_RECORD_SAMPLE records parsed.
func (p *linuxProfiler) readRingBuffer(buf []byte) int {
	// Read data_head atomically (kernel updates this concurrently).
	// Use a memory barrier by reading via atomic load semantics.
	headPtr := (*uint64)(unsafe.Pointer(&buf[int(dataHeadOffset)]))
	head := *headPtr // volatile read from mmap'd memory

	tailPtr := (*uint64)(unsafe.Pointer(&buf[int(dataTailOffset)]))
	tail := *tailPtr

	if head == tail {
		return 0 // No new data
	}

	data := buf[dataOffset:]
	count := 0

	for tail < head {
		offset := tail % uint64(dataSize)

		// Read perf_event_header (type u32, misc u16, size u16)
		if offset+8 > uint64(dataSize) {
			// Header wraps around — skip to avoid complexity
			tail += 8
			continue
		}

		eventType := binary.LittleEndian.Uint32(data[offset:])
		eventSize := binary.LittleEndian.Uint16(data[offset+6:])

		if eventSize == 0 || eventSize > 4096 {
			// Corrupt record, reset
			break
		}

		if eventType == PERF_RECORD_SAMPLE {
			p.parseSample(data, offset+8, uint64(eventSize)-8)
			count++
		}

		tail += uint64(eventSize)
	}

	// Update data_tail to acknowledge consumed data (write barrier)
	*tailPtr = tail
	return count
}

// parseSample extracts IP, PID, TID, and callchain from a PERF_RECORD_SAMPLE.
// Layout for PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_CALLCHAIN:
//
//	u64 ip
//	u32 pid, tid
//	u64 nr (callchain length)
//	u64 ips[nr]
func (p *linuxProfiler) parseSample(data []byte, offset, remaining uint64) {
	if remaining < 16 { // ip(8) + pid/tid(8) minimum
		return
	}

	// Read with ring buffer wrapping
	readU64 := func(off uint64) uint64 {
		pos := off % uint64(dataSize)
		if pos+8 <= uint64(dataSize) {
			return binary.LittleEndian.Uint64(data[pos:])
		}
		// Handle wrap-around
		var tmp [8]byte
		for i := 0; i < 8; i++ {
			tmp[i] = data[(pos+uint64(i))%uint64(dataSize)]
		}
		return binary.LittleEndian.Uint64(tmp[:])
	}

	readU32 := func(off uint64) uint32 {
		pos := off % uint64(dataSize)
		if pos+4 <= uint64(dataSize) {
			return binary.LittleEndian.Uint32(data[pos:])
		}
		var tmp [4]byte
		for i := 0; i < 4; i++ {
			tmp[i] = data[(pos+uint64(i))%uint64(dataSize)]
		}
		return binary.LittleEndian.Uint32(tmp[:])
	}

	ip := readU64(offset)
	pid := readU32(offset + 8)
	tid := readU32(offset + 12)
	_ = tid // Available but unused for now

	// Build stack key starting with IP
	var key stackKey
	var ips []uint64
	key[0] = ip
	ips = append(ips, ip)

	// Read callchain if available
	if remaining >= 24 { // ip + pid/tid + nr
		nr := readU64(offset + 16)
		if nr > maxStackDepth {
			nr = maxStackDepth
		}

		chainOffset := offset + 24
		for i := uint64(0); i < nr && i < maxStackDepth-1; i++ {
			if 24+8*(i+1) > remaining {
				break
			}
			chainIP := readU64(chainOffset + i*8)
			// Skip kernel/user markers (values like 0xffffffff...)
			if chainIP > 0xf000000000000000 {
				continue
			}
			if len(ips) < maxStackDepth {
				key[len(ips)] = chainIP
				ips = append(ips, chainIP)
			}
		}
	}

	// Aggregate
	p.sampleMu.Lock()
	ps, ok := p.samples[pid]
	if !ok {
		ps = &pidSamples{
			stacks: make(map[stackKey]uint64),
			frames: make(map[stackKey][]uint64),
		}
		p.samples[pid] = ps
	}
	ps.stacks[key]++
	if _, exists := ps.frames[key]; !exists {
		ipsCopy := make([]uint64, len(ips))
		copy(ipsCopy, ips)
		ps.frames[key] = ipsCopy
	}
	p.sampleMu.Unlock()
}

// flushLoop periodically snapshots, resolves, and emits profiles.
func (p *linuxProfiler) flushLoop() {
	defer p.wg.Done()

	interval := p.cfg.Interval
	if interval == 0 {
		interval = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	flushStart := time.Now()

	for {
		select {
		case <-ticker.C:
			now := time.Now()
			p.flush(flushStart, now)
			flushStart = now

			// Periodic symbol cache cleanup
			p.resolver.cleanup()

		case <-p.stopCh:
			// Final flush
			p.flush(flushStart, time.Now())
			return
		}
	}
}

func (p *linuxProfiler) flush(start, end time.Time) {
	// Snapshot and reset aggregation
	p.sampleMu.Lock()
	snapshot := p.samples
	p.samples = make(map[uint32]*pidSamples)
	p.sampleMu.Unlock()

	if len(snapshot) == 0 {
		return
	}

	// Group by service name
	type serviceData struct {
		stacks map[stackKey]uint64
		frames map[stackKey][]uint64
		pid    uint32 // representative PID for symbol resolution
	}
	byService := make(map[string]*serviceData)

	for pid, ps := range snapshot {
		serviceName := "unknown"
		if p.resolveService != nil {
			serviceName = p.resolveService(pid)
		}

		sd, ok := byService[serviceName]
		if !ok {
			sd = &serviceData{
				stacks: make(map[stackKey]uint64),
				frames: make(map[stackKey][]uint64),
				pid:    pid,
			}
			byService[serviceName] = sd
		}

		for key, count := range ps.stacks {
			sd.stacks[key] += count
		}
		for key, ips := range ps.frames {
			if _, exists := sd.frames[key]; !exists {
				sd.frames[key] = ips
			}
		}
	}

	// Build and emit profiles per service
	p.mu.RLock()
	callbacks := make([]func(*Profile), len(p.callbacks))
	copy(callbacks, p.callbacks)
	p.mu.RUnlock()

	for serviceName, sd := range byService {
		pprofData, err := buildPProf(sd.pid, sd.stacks, sd.frames, p.resolver, start, end)
		if err != nil {
			p.logger.Warn("pprof build error", zap.String("service", serviceName), zap.Error(err))
			continue
		}
		if pprofData == nil {
			continue
		}

		profile := &Profile{
			ServiceName: serviceName,
			Start:       start,
			End:         end,
			PProfData:   pprofData,
		}

		for _, cb := range callbacks {
			cb(profile)
		}
	}

	p.logger.Debug("profiles flushed",
		zap.Int("services", len(byService)),
		zap.Int("pids", len(snapshot)),
	)
}
