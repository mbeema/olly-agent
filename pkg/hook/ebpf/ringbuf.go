//go:build linux

package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"

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
	_pad        [3]byte
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
	Payload     [256]byte
}

const ollyEventSize = 4 + 4 + 4 + 4 + 4 + 4 + 8 + 4 + 2 + 1 + 1 + 256 // 296 bytes

// eventReader wraps a BPF ring buffer reader and dispatches events to Callbacks.
type eventReader struct {
	reader    *ringbuf.Reader
	callbacks hook.Callbacks
	logger    *zap.Logger
}

// newEventReader creates a ring buffer reader for the given BPF map.
func newEventReader(eventsMap *ebpf.Map, callbacks hook.Callbacks, logger *zap.Logger) (*eventReader, error) {
	rd, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}
	return &eventReader{
		reader:    rd,
		callbacks: callbacks,
		logger:    logger,
	}, nil
}

// readLoop reads events from the ring buffer and dispatches to callbacks.
// It blocks until the reader is closed or an unrecoverable error occurs.
func (er *eventReader) readLoop() {
	for {
		record, err := er.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			er.logger.Debug("ring buffer read error", zap.Error(err))
			continue
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

	// Extract payload
	var payload []byte
	const payloadOffset = 40 // after all header fields including direction + pad2
	if payloadLen > 0 && len(raw) >= int(payloadOffset+payloadLen) {
		payload = make([]byte, payloadLen)
		copy(payload, raw[payloadOffset:payloadOffset+payloadLen])
	}

	switch eventType {
	case eventConnect:
		if fd == -1 {
			// Sentinel from sched_process_exec tracepoint — trigger SSL scan.
			// This is handled by the SSL scanner in provider.go.
			return
		}
		if er.callbacks.OnConnect != nil {
			er.callbacks.OnConnect(pid, tid, fd, remoteAddr, remotePort, ts)
		}

	case eventAccept:
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

// close closes the ring buffer reader.
func (er *eventReader) close() error {
	return er.reader.Close()
}
