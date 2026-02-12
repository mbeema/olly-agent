// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/mbeema/olly/pkg/hook"
	"go.uber.org/zap"
)

// Event types — must match the constants in olly.bpf.c.
const (
	eventConnect  = 1
	eventDataOut  = 2
	eventDataIn   = 3
	eventClose    = 4
	eventSSLOut   = 5
	eventSSLIn    = 6
	eventAccept   = 7
	eventLogWrite = 8
)

// ollyEvent is the Go representation of struct olly_event from BPF.
// It matches the exact memory layout of the C struct.
type ollyEvent struct {
	EventType   uint8
	HasTraceCtx uint8
	_pad        [2]byte
	PID         uint32
	TID         uint32
	FD          int32
	PayloadLen  uint32
	OriginalLen uint32
	TimestampNS uint64
	RemoteAddr  uint32
	RemotePort  uint16
	Direction   uint8
	_pad2       uint8
	TraceID     [32]byte
	SpanID      [16]byte
	Payload     [256]byte
}

const ollyEventSize = 4 + 4 + 4 + 4 + 4 + 4 + 8 + 4 + 2 + 1 + 1 + 32 + 16 + 256 // 344 bytes

// eventTraceCtx holds BPF-generated trace context extracted from a ring buffer event.
type eventTraceCtx struct {
	TraceID string
	SpanID  string
}

// eventReader wraps a BPF ring buffer reader and dispatches events to Callbacks.
type eventReader struct {
	reader    *ringbuf.Reader
	callbacks hook.Callbacks
	logger    *zap.Logger

	// lastTraceCtx stores BPF-generated trace context from ring buffer events,
	// keyed by pid+tid. This is set synchronously in dispatch() before calling
	// OnDataIn, so the agent can read it race-free in the same goroutine.
	lastTraceCtx   map[uint64]*eventTraceCtx
	lastTraceCtxMu sync.Mutex
}

// newEventReader creates a ring buffer reader for the given BPF map.
func newEventReader(eventsMap *ebpf.Map, callbacks hook.Callbacks, logger *zap.Logger) (*eventReader, error) {
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}
	return &eventReader{
		reader:       rd,
		callbacks:    callbacks,
		logger:       logger,
		lastTraceCtx: make(map[uint64]*eventTraceCtx),
	}, nil
}

// readLoop reads events from the ring buffer and dispatches to callbacks.
// It blocks until the reader is closed or an unrecoverable error occurs.
func (er *eventReader) readLoop() {
	er.logger.Info("ring buffer reader started")
	eventCount := uint64(0)
	for {
		record, err := er.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				er.logger.Info("ring buffer reader closed", zap.Uint64("total_events", eventCount))
				return
			}
			er.logger.Debug("ring buffer read error", zap.Error(err))
			continue
		}

		eventCount++
		if eventCount <= 5 || eventCount%1000 == 0 {
			er.logger.Debug("ring buffer event",
				zap.Uint64("count", eventCount),
				zap.Int("raw_len", len(record.RawSample)),
			)
		}

		er.dispatch(record.RawSample)
	}
}

// dispatch parses a raw ring buffer sample and calls the appropriate callback.
func (er *eventReader) dispatch(raw []byte) {
	if len(raw) < 36 { // minimum event header size (without payload)
		er.logger.Debug("event too short", zap.Int("len", len(raw)))
		return
	}

	eventType := raw[0]
	hasTraceCtx := raw[1]
	pid := binary.LittleEndian.Uint32(raw[4:8])
	tid := binary.LittleEndian.Uint32(raw[8:12])
	fd := int32(binary.LittleEndian.Uint32(raw[12:16]))
	payloadLen := binary.LittleEndian.Uint32(raw[16:20])
	// originalLen at raw[20:24] — available for truncation detection
	ts := binary.LittleEndian.Uint64(raw[24:32])
	remoteAddr := binary.LittleEndian.Uint32(raw[32:36])

	var remotePort uint16
	if len(raw) >= 38 {
		remotePort = binary.LittleEndian.Uint16(raw[36:38])
	}

	// Parse BPF-embedded trace context (trace_id at offset 40, span_id at offset 72)
	if hasTraceCtx == 1 && len(raw) >= 88 {
		traceID := string(raw[40:72])
		spanID := string(raw[72:88])
		key := uint64(pid)<<32 | uint64(tid)
		er.lastTraceCtxMu.Lock()
		er.lastTraceCtx[key] = &eventTraceCtx{
			TraceID: traceID,
			SpanID:  spanID,
		}
		er.lastTraceCtxMu.Unlock()
	}

	// Extract payload (offset shifted by 48 bytes for trace_id[32] + span_id[16])
	var payload []byte
	const payloadOffset = 88 // after all header fields including trace_id + span_id
	if payloadLen > 0 && len(raw) >= int(payloadOffset+payloadLen) {
		payload = make([]byte, payloadLen)
		copy(payload, raw[payloadOffset:payloadOffset+payloadLen])
	}

	switch eventType {
	case eventConnect:
		if fd == -1 {
			// Sentinel from sched_process_exec tracepoint — trigger SSL scan.
			return
		}
		er.logger.Debug("dispatch CONNECT", zap.Uint32("pid", pid), zap.Int32("fd", fd), zap.Uint32("addr", remoteAddr), zap.Uint16("port", remotePort))
		if er.callbacks.OnConnect != nil {
			er.callbacks.OnConnect(pid, tid, fd, remoteAddr, remotePort, ts)
		}

	case eventAccept:
		er.logger.Debug("dispatch ACCEPT", zap.Uint32("pid", pid), zap.Int32("fd", fd))
		if er.callbacks.OnAccept != nil {
			er.callbacks.OnAccept(pid, tid, fd, remoteAddr, remotePort, ts)
		}

	case eventDataOut, eventSSLOut:
		if er.callbacks.OnDataOut != nil && len(payload) > 0 {
			er.callbacks.OnDataOut(pid, tid, fd, payload, ts)
		}

	case eventDataIn, eventSSLIn:
		if er.callbacks.OnDataIn != nil && len(payload) > 0 {
			er.callbacks.OnDataIn(pid, tid, fd, payload, ts)
		}

	case eventClose:
		if er.callbacks.OnClose != nil {
			er.callbacks.OnClose(pid, tid, fd, ts)
		}

	case eventLogWrite:
		if er.callbacks.OnLogWrite != nil && len(payload) > 0 {
			er.callbacks.OnLogWrite(pid, tid, fd, payload, ts)
		}
	}
}

// getEventTraceContext returns BPF-generated trace context from the most recent
// ring buffer event for the given pid+tid. The context is consumed (deleted)
// on read, ensuring each event's context is used exactly once.
func (er *eventReader) getEventTraceContext(pid, tid uint32) (traceID, spanID string, ok bool) {
	key := uint64(pid)<<32 | uint64(tid)
	er.lastTraceCtxMu.Lock()
	ctx, exists := er.lastTraceCtx[key]
	if exists {
		delete(er.lastTraceCtx, key)
	}
	er.lastTraceCtxMu.Unlock()
	if !exists || ctx == nil {
		return "", "", false
	}
	return ctx.TraceID, ctx.SpanID, true
}

// close closes the ring buffer reader.
func (er *eventReader) close() error {
	return er.reader.Close()
}
