// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package reassembly

import (
	"sync"
	"time"
)

// MaxBufferSize is the maximum bytes buffered per direction.
const MaxBufferSize = 256 * 1024 // 256KB

// Stream buffers send and receive data for a single connection.
type Stream struct {
	mu sync.Mutex

	PID        uint32
	FD         int32
	RemoteAddr string
	RemotePort uint16
	IsSSL      bool

	sendBuf  []byte
	recvBuf  []byte
	lastSend time.Time
	lastRecv time.Time

	// Protocol detected for this connection
	Protocol string
}

// NewStream creates a new stream for a connection.
func NewStream(pid uint32, fd int32, remoteAddr string, remotePort uint16) *Stream {
	return &Stream{
		PID:        pid,
		FD:         fd,
		RemoteAddr: remoteAddr,
		RemotePort: remotePort,
		sendBuf:    make([]byte, 0, 4096),
		recvBuf:    make([]byte, 0, 4096),
	}
}

// AppendSend adds data to the send buffer.
func (s *Stream) AppendSend(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	remaining := MaxBufferSize - len(s.sendBuf)
	if remaining <= 0 {
		return
	}
	if len(data) > remaining {
		data = data[:remaining]
	}

	s.sendBuf = append(s.sendBuf, data...)
	s.lastSend = time.Now()
}

// AppendRecv adds data to the recv buffer.
func (s *Stream) AppendRecv(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	remaining := MaxBufferSize - len(s.recvBuf)
	if remaining <= 0 {
		return
	}
	if len(data) > remaining {
		data = data[:remaining]
	}

	s.recvBuf = append(s.recvBuf, data...)
	s.lastRecv = time.Now()
}

// SendBytes returns the current send buffer contents.
func (s *Stream) SendBytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendBuf
}

// RecvBytes returns the current recv buffer contents.
func (s *Stream) RecvBytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recvBuf
}

// ConsumeSend removes n bytes from the front of the send buffer.
func (s *Stream) ConsumeSend(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if n >= len(s.sendBuf) {
		s.sendBuf = s.sendBuf[:0]
	} else {
		s.sendBuf = s.sendBuf[n:]
	}
}

// ConsumeRecv removes n bytes from the front of the recv buffer.
func (s *Stream) ConsumeRecv(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if n >= len(s.recvBuf) {
		s.recvBuf = s.recvBuf[:0]
	} else {
		s.recvBuf = s.recvBuf[n:]
	}
}

// HasData returns true if either buffer has data.
func (s *Stream) HasData() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sendBuf) > 0 || len(s.recvBuf) > 0
}

// Reset clears both buffers.
func (s *Stream) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendBuf = s.sendBuf[:0]
	s.recvBuf = s.recvBuf[:0]
}

// LastActivity returns the most recent send or recv time.
func (s *Stream) LastActivity() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.lastRecv.After(s.lastSend) {
		return s.lastRecv
	}
	return s.lastSend
}
