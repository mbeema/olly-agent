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
	objs         *ollyObjects
	links        []link.Link
	skMsgAttached bool // true if sk_msg was attached via BPF_PROG_ATTACH
	logger       *zap.Logger
}

// newLoader creates a loader but does not yet load anything.
func newLoader(logger *zap.Logger) *loader {
	return &loader{logger: logger}
}

// load loads the compiled eBPF objects (programs + maps) into the kernel.
func (l *loader) load() error {
	l.objs = &ollyObjects{}
	if err := loadOllyObjects(l.objs, &ebpf.CollectionOptions{}); err != nil {
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
	tp, err := link.Tracepoint("sched", "sched_process_exec", l.objs.TracepointSchedProcessExec, nil)
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
	// Detach sk_msg (attached via BPF_PROG_ATTACH, not link-based)
	if l.skMsgAttached && l.objs != nil && l.objs.OllySkMsg != nil && l.objs.SockOpsMap != nil {
		_ = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  l.objs.SockOpsMap.FD(),
			Program: l.objs.OllySkMsg,
			Attach:  ebpf.AttachSkMsgVerdict,
		})
		l.skMsgAttached = false
	}

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

// ──────────────────────────────────────────────────────────────────────
// Traceparent injection: sockops + sk_msg attachment
// ──────────────────────────────────────────────────────────────────────

// attachSockopsAndSkMsg attaches the sockops program to the root cgroup and
// the sk_msg program to the sockhash map for traceparent injection.
// This is non-fatal — if it fails, the agent falls back to trace stitching.
func (l *loader) attachSockopsAndSkMsg(cgroupPath string) error {
	if l.objs.OllySockops == nil || l.objs.OllySkMsg == nil {
		return fmt.Errorf("sockops/sk_msg programs not loaded")
	}
	if l.objs.SockOpsMap == nil {
		return fmt.Errorf("sock_ops_map not loaded")
	}

	// Attach sockops to cgroup
	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: l.objs.OllySockops,
	})
	if err != nil {
		return fmt.Errorf("attach sockops to cgroup %s: %w", cgroupPath, err)
	}
	l.links = append(l.links, sockopsLink)
	l.logger.Debug("attached sockops to cgroup", zap.String("path", cgroupPath))

	// Attach sk_msg to the sockhash map using BPF_PROG_ATTACH (legacy path).
	// BPF_LINK_CREATE for sk_msg requires kernel 6.7+; kernel 6.1 only
	// supports the legacy BPF_PROG_ATTACH via link.RawAttachProgram.
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  l.objs.SockOpsMap.FD(),
		Program: l.objs.OllySkMsg,
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	if err != nil {
		return fmt.Errorf("attach sk_msg to sockhash: %w", err)
	}
	l.skMsgAttached = true
	l.logger.Debug("attached sk_msg to sockhash")

	return nil
}

// threadKey mirrors the BPF struct thread_key for map operations.
type threadKey struct {
	PID uint32
	TID uint32
}

// traceparentHeaderLen must match TRACEPARENT_HEADER_LEN in olly.bpf.c.
const traceparentHeaderLen = 70

// traceCtx mirrors the BPF struct trace_ctx for map operations.
// Must match generated ollyTraceCtx exactly (including padding).
// Fields must be exported for encoding/binary to marshal/unmarshal.
type traceCtx struct {
	Valid     uint8
	Pad       [3]byte
	HeaderLen uint32
	Header    [traceparentHeaderLen + 1]byte
	Pad2      [1]byte // alignment padding to match BPF struct
}

// setTraceContext writes a pre-formatted traceparent header to the BPF map
// for the given PID+TID. The sk_msg program reads this when the thread
// makes an outbound HTTP request.
func (l *loader) setTraceContext(pid, tid uint32, traceparentHeader string) error {
	if l.objs.ThreadTraceCtx == nil {
		return fmt.Errorf("thread_trace_ctx map not loaded")
	}

	key := threadKey{PID: pid, TID: tid}
	val := traceCtx{
		Valid:     1,
		HeaderLen: uint32(len(traceparentHeader)),
	}

	// Copy header string into fixed-size array
	headerBytes := []byte(traceparentHeader)
	n := len(headerBytes)
	if n > traceparentHeaderLen {
		n = traceparentHeaderLen
	}
	copy(val.Header[:n], headerBytes[:n])

	return l.objs.ThreadTraceCtx.Put(key, val)
}

// clearTraceContext removes the trace context for a PID+TID from the BPF map.
func (l *loader) clearTraceContext(pid, tid uint32) error {
	if l.objs.ThreadTraceCtx == nil {
		return nil
	}
	key := threadKey{PID: pid, TID: tid}
	return l.objs.ThreadTraceCtx.Delete(key)
}

// getTraceContext reads the BPF-generated trace context for a PID+TID.
// Returns traceID, spanID, ok. The header format from BPF is:
// "traceparent: 00-{traceID}-{spanID}-01\r\n"
func (l *loader) getTraceContext(pid, tid uint32) (string, string, bool) {
	if l.objs.ThreadTraceCtx == nil {
		return "", "", false
	}
	key := threadKey{PID: pid, TID: tid}
	var val traceCtx
	if err := l.objs.ThreadTraceCtx.Lookup(key, &val); err != nil {
		return "", "", false
	}
	if val.Valid == 0 || val.HeaderLen == 0 {
		return "", "", false
	}

	// Parse "traceparent: 00-{32hex}-{16hex}-01\r\n"
	header := string(val.Header[:val.HeaderLen])
	// Expected prefix: "traceparent: 00-" (16 chars)
	if len(header) < 52 { // 16 + 32 + 1 + 16 + 1 + 2 = 68 minimum + \r\n
		return "", "", false
	}
	// Find the trace ID and span ID
	const prefix = "traceparent: 00-"
	if len(header) < len(prefix)+32+1+16 {
		return "", "", false
	}
	traceID := header[len(prefix) : len(prefix)+32]
	spanID := header[len(prefix)+32+1 : len(prefix)+32+1+16]
	return traceID, spanID, true
}

// Helper to convert IP uint32 to byte order.
func ipToBytes(ip uint32) [4]byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], ip)
	return b
}
