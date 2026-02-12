// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package conntrack

import (
	"fmt"
	"sync"
	"time"
)

// ConnDirection indicates whether a connection was initiated or accepted.
type ConnDirection int

const (
	ConnOutbound ConnDirection = iota // Local process called connect()
	ConnInbound                       // Local process accepted via accept()
)

// ConnInfo holds metadata about a tracked connection.
type ConnInfo struct {
	PID         uint32
	FD          int32
	RemoteAddr  uint32 // IPv4 in host byte order
	RemotePort  uint16
	ConnectTime time.Time
	BytesSent   uint64
	BytesRecv   uint64
	IsSSL       bool

	// R2.3 fix: Track whether connection is inbound (accept) or outbound (connect).
	Direction ConnDirection

	// F3 fix: Adaptive protocol learning.
	// Once detected, remember the protocol for this connection.
	Protocol string
}

// RemoteAddrStr returns the remote address as a dotted-quad string.
func (c *ConnInfo) RemoteAddrStr() string {
	return fmt.Sprintf("%d.%d.%d.%d",
		c.RemoteAddr&0xFF,
		(c.RemoteAddr>>8)&0xFF,
		(c.RemoteAddr>>16)&0xFF,
		(c.RemoteAddr>>24)&0xFF,
	)
}

// RemoteStr returns "addr:port" string.
func (c *ConnInfo) RemoteStr() string {
	return fmt.Sprintf("%s:%d", c.RemoteAddrStr(), c.RemotePort)
}

// connKey uniquely identifies a connection by PID and FD.
type connKey struct {
	PID uint32
	FD  int32
}

// maxTrackedConns limits the number of tracked connections to prevent
// unbounded memory growth under connection storms.
const maxTrackedConns = 100000

// Tracker maps (pid, fd) to connection metadata.
type Tracker struct {
	mu    sync.RWMutex
	conns map[connKey]*ConnInfo
}

// NewTracker creates a new connection tracker.
func NewTracker() *Tracker {
	return &Tracker{
		conns: make(map[connKey]*ConnInfo),
	}
}

// Register records a new outbound connection (from connect()).
func (t *Tracker) Register(pid uint32, fd int32, remoteAddr uint32, remotePort uint16) *ConnInfo {
	key := connKey{PID: pid, FD: fd}

	info := &ConnInfo{
		PID:         pid,
		FD:          fd,
		RemoteAddr:  remoteAddr,
		RemotePort:  remotePort,
		ConnectTime: time.Now(),
		Direction:   ConnOutbound,
	}

	t.mu.Lock()
	if len(t.conns) >= maxTrackedConns {
		// Evict the oldest connection to stay within bounds
		t.evictOldestLocked()
	}
	t.conns[key] = info
	t.mu.Unlock()

	return info
}

// RegisterInbound records a new inbound connection (from accept()).
func (t *Tracker) RegisterInbound(pid uint32, fd int32, remoteAddr uint32, remotePort uint16) *ConnInfo {
	key := connKey{PID: pid, FD: fd}

	info := &ConnInfo{
		PID:         pid,
		FD:          fd,
		RemoteAddr:  remoteAddr,
		RemotePort:  remotePort,
		ConnectTime: time.Now(),
		Direction:   ConnInbound,
	}

	t.mu.Lock()
	if len(t.conns) >= maxTrackedConns {
		t.evictOldestLocked()
	}
	t.conns[key] = info
	t.mu.Unlock()

	return info
}

// Lookup returns the connection info for the given PID and FD.
func (t *Tracker) Lookup(pid uint32, fd int32) *ConnInfo {
	key := connKey{PID: pid, FD: fd}

	t.mu.RLock()
	info := t.conns[key]
	t.mu.RUnlock()

	return info
}

// AddBytesSent adds to the bytes sent counter for a connection.
func (t *Tracker) AddBytesSent(pid uint32, fd int32, n uint64) {
	key := connKey{PID: pid, FD: fd}

	t.mu.Lock()
	if info, ok := t.conns[key]; ok {
		info.BytesSent += n
	}
	t.mu.Unlock()
}

// AddBytesRecv adds to the bytes received counter for a connection.
func (t *Tracker) AddBytesRecv(pid uint32, fd int32, n uint64) {
	key := connKey{PID: pid, FD: fd}

	t.mu.Lock()
	if info, ok := t.conns[key]; ok {
		info.BytesRecv += n
	}
	t.mu.Unlock()
}

// MarkSSL marks a connection as using SSL/TLS.
func (t *Tracker) MarkSSL(pid uint32, fd int32) {
	key := connKey{PID: pid, FD: fd}

	t.mu.Lock()
	if info, ok := t.conns[key]; ok {
		info.IsSSL = true
	}
	t.mu.Unlock()
}

// SetProtocol stores the detected protocol for a connection (adaptive learning).
func (t *Tracker) SetProtocol(pid uint32, fd int32, proto string) {
	key := connKey{PID: pid, FD: fd}

	t.mu.Lock()
	if info, ok := t.conns[key]; ok {
		info.Protocol = proto
	}
	t.mu.Unlock()
}

// GetProtocol returns the cached protocol for a connection, or empty string.
func (t *Tracker) GetProtocol(pid uint32, fd int32) string {
	key := connKey{PID: pid, FD: fd}

	t.mu.RLock()
	info := t.conns[key]
	t.mu.RUnlock()

	if info != nil {
		return info.Protocol
	}
	return ""
}

// Remove removes a connection and returns its final info.
func (t *Tracker) Remove(pid uint32, fd int32) *ConnInfo {
	key := connKey{PID: pid, FD: fd}

	t.mu.Lock()
	info := t.conns[key]
	delete(t.conns, key)
	t.mu.Unlock()

	return info
}

// Count returns the number of active connections.
func (t *Tracker) Count() int {
	t.mu.RLock()
	n := len(t.conns)
	t.mu.RUnlock()
	return n
}

// evictOldestLocked removes the oldest connection. Must be called under t.mu.
func (t *Tracker) evictOldestLocked() {
	var oldestKey connKey
	var oldestTime time.Time
	first := true
	for k, info := range t.conns {
		if first || info.ConnectTime.Before(oldestTime) {
			oldestKey = k
			oldestTime = info.ConnectTime
			first = false
		}
	}
	if !first {
		delete(t.conns, oldestKey)
	}
}

// CleanStale removes connections older than maxAge.
func (t *Tracker) CleanStale(maxAge time.Duration) int {
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	t.mu.Lock()
	for key, info := range t.conns {
		if info.ConnectTime.Before(cutoff) {
			delete(t.conns, key)
			removed++
		}
	}
	t.mu.Unlock()

	return removed
}
