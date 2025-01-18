//go:build linux

package ebpf

import (
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.uber.org/zap"
)

// loader manages BPF object lifecycle: loading programs, creating maps, and
// attaching kprobes/kretprobes.
type loader struct {
	objs  *ollyObjects
	links []link.Link
	logger *zap.Logger
}

// newLoader creates a loader but does not yet load anything.
func newLoader(logger *zap.Logger) *loader {
	return &loader{logger: logger}
}

// load loads the compiled eBPF objects (programs + maps) into the kernel.
func (l *loader) load() error {
	l.objs = &ollyObjects{}
	if err := loadOllyObjects(l.objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			// Pin maps to /sys/fs/bpf if needed in the future
		},
	}); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	return nil
}

// attachSyscallProbes attaches kprobes to all syscall entry/exit points.
func (l *loader) attachSyscallProbes() error {
	type probeSpec struct {
		name    string
		prog    *ebpf.Program
		isRet   bool
	}

	probes := []probeSpec{
		// connect
		{"sys_connect", l.objs.KprobeConnect, false},
		{"sys_connect", l.objs.KretprobeConnect, true},
		// accept4
		{"sys_accept4", l.objs.KprobeAccept4, false},
		{"sys_accept4", l.objs.KretprobeAccept4, true},
		// accept
		{"sys_accept", l.objs.KprobeAccept, false},
		{"sys_accept", l.objs.KretprobeAccept, true},
		// write
		{"sys_write", l.objs.KprobeWrite, false},
		// sendto
		{"sys_sendto", l.objs.KprobeSendto, false},
		// read
		{"sys_read", l.objs.KprobeRead, false},
		{"sys_read", l.objs.KretprobeRead, true},
		// recvfrom
		{"sys_recvfrom", l.objs.KprobeRecvfrom, false},
		{"sys_recvfrom", l.objs.KretprobeRecvfrom, true},
		// close
		{"sys_close", l.objs.KprobeClose, false},
	}

	for _, p := range probes {
		if p.prog == nil {
			l.logger.Debug("skipping nil program", zap.String("probe", p.name))
			continue
		}

		var lnk link.Link
		var err error

		if p.isRet {
			lnk, err = link.Kretprobe(p.name, p.prog, nil)
		} else {
			lnk, err = link.Kprobe(p.name, p.prog, nil)
		}
		if err != nil {
			// Try __x64_ prefix for newer kernels
			altName := "__x64_" + p.name
			if p.isRet {
				lnk, err = link.Kretprobe(altName, p.prog, nil)
			} else {
				lnk, err = link.Kprobe(altName, p.prog, nil)
			}
			if err != nil {
				return fmt.Errorf("attach kprobe %s: %w", p.name, err)
			}
			l.logger.Debug("attached with alternate name", zap.String("name", altName))
		}

		l.links = append(l.links, lnk)
		kind := "kprobe"
		if p.isRet {
			kind = "kretprobe"
		}
		l.logger.Debug("attached probe", zap.String("kind", kind), zap.String("name", p.name))
	}

	return nil
}

// attachTracepoints attaches to tracepoints (process exec).
func (l *loader) attachTracepoints() error {
	tp, err := link.Tracepoint("sched", "sched_process_exec", l.objs.TracepointSchedSchedProcessExec, nil)
	if err != nil {
		l.logger.Warn("failed to attach sched_process_exec tracepoint (SSL auto-discovery disabled)", zap.Error(err))
		return nil // non-fatal
	}
	l.links = append(l.links, tp)
	l.logger.Debug("attached tracepoint", zap.String("name", "sched/sched_process_exec"))
	return nil
}

// setTracingEnabled writes the tracing toggle to the BPF map.
func (l *loader) setTracingEnabled(enabled bool) error {
	key := uint32(0)
	var val uint32
	if enabled {
		val = 1
	}
	return l.objs.TracingEnabled.Put(key, val)
}

// isTracingEnabled reads the tracing toggle from the BPF map.
func (l *loader) isTracingEnabled() bool {
	key := uint32(0)
	var val uint32
	if err := l.objs.TracingEnabled.Lookup(key, &val); err != nil {
		return false
	}
	return val == 1
}

// addPIDFilter adds a PID to the filter map.
func (l *loader) addPIDFilter(pid uint32) error {
	val := uint8(1)
	return l.objs.PidFilter.Put(pid, val)
}

// removePIDFilter removes a PID from the filter map.
func (l *loader) removePIDFilter(pid uint32) error {
	return l.objs.PidFilter.Delete(pid)
}

// addLogFD marks an fd as a log file descriptor.
func (l *loader) addLogFD(pid uint32, fd int32) error {
	key := connKey{PID: pid, FD: fd}
	val := uint8(1)
	return l.objs.LogFdMap.Put(key, val)
}

// lookupConn retrieves connection info for a {pid, fd} pair.
func (l *loader) lookupConn(pid uint32, fd int32) (*connVal, error) {
	key := connKey{PID: pid, FD: fd}
	var val connVal
	if err := l.objs.ConnMap.Lookup(key, &val); err != nil {
		return nil, err
	}
	return &val, nil
}

// close releases all probes, links, and BPF objects.
func (l *loader) close() {
	for _, lnk := range l.links {
		lnk.Close()
	}
	l.links = nil

	if l.objs != nil {
		l.objs.Close()
		l.objs = nil
	}
}

// connKey mirrors the BPF struct conn_key for map lookups.
type connKey struct {
	PID uint32
	FD  int32
}

// connVal mirrors the BPF struct conn_val.
type connVal struct {
	Addr uint32
	Port uint16
	Dir  uint8
	_    uint8
}

// sslFDKey is the SSL* pointer used as key in ssl_fd_map.
type sslFDKey = uint64

// attachSSLUprobes attaches uprobes to a specific libssl.so for SSL_set_fd,
// SSL_write, and SSL_read.
func (l *loader) attachSSLUprobes(libPath string) error {
	ex, err := link.OpenExecutable(libPath)
	if err != nil {
		return fmt.Errorf("open %s: %w", libPath, err)
	}

	type uprobeSpec struct {
		symbol string
		prog   *ebpf.Program
		isRet  bool
	}

	uprbs := []uprobeSpec{
		{"SSL_set_fd", l.objs.UprobeSslSetFd, false},
		{"SSL_write", l.objs.UprobeSslWrite, false},
		{"SSL_write", l.objs.UretprobeSslWrite, true},
		{"SSL_read", l.objs.UprobeSslRead, false},
		{"SSL_read", l.objs.UretprobeSslRead, true},
	}

	for _, u := range uprbs {
		if u.prog == nil {
			continue
		}

		var lnk link.Link
		if u.isRet {
			lnk, err = ex.Uretprobe(u.symbol, u.prog, nil)
		} else {
			lnk, err = ex.Uprobe(u.symbol, u.prog, nil)
		}
		if err != nil {
			l.logger.Warn("failed to attach SSL uprobe",
				zap.String("symbol", u.symbol),
				zap.String("lib", libPath),
				zap.Error(err),
			)
			continue
		}
		l.links = append(l.links, lnk)
		kind := "uprobe"
		if u.isRet {
			kind = "uretprobe"
		}
		l.logger.Debug("attached SSL probe",
			zap.String("kind", kind),
			zap.String("symbol", u.symbol),
			zap.String("lib", libPath),
		)
	}

	return nil
}

// eventRingBuf returns the ring buffer map for the event reader.
func (l *loader) eventRingBuf() *ebpf.Map {
	return l.objs.Events
}

// Helper to convert IP uint32 to byte order.
func ipToBytes(ip uint32) [4]byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ip)
	return b
}
