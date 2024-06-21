package hook

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"go.uber.org/zap"
)

// Callbacks for hook events.
type Callbacks struct {
	OnConnect func(pid, tid uint32, fd int32, remoteAddr uint32, remotePort uint16, ts uint64)
	OnAccept  func(pid, tid uint32, fd int32, remoteAddr uint32, remotePort uint16, ts uint64) // R2.3: inbound
	OnDataOut func(pid, tid uint32, fd int32, data []byte, ts uint64)
	OnDataIn  func(pid, tid uint32, fd int32, data []byte, ts uint64)
	OnClose    func(pid, tid uint32, fd int32, ts uint64)
	OnLogWrite func(pid, tid uint32, fd int32, data []byte, ts uint64) // R6: log write capture
}

// Manager listens on a Unix DGRAM socket for hook events from libolly.so.
// H3 fix: Uses a pool of reader goroutines for high-throughput dispatch.
type Manager struct {
	socketPath string
	logger     *zap.Logger
	callbacks  Callbacks
	numWorkers int

	conn    *net.UnixConn
	control *ControlFile
	wg      sync.WaitGroup
	stopCh  chan struct{}
}

// NewManager creates a new hook manager.
func NewManager(socketPath string, callbacks Callbacks, logger *zap.Logger) *Manager {
	// Use at least 2 workers, up to GOMAXPROCS
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 {
		workers = 2
	}
	if workers > 8 {
		workers = 8
	}

	return &Manager{
		socketPath: socketPath,
		logger:     logger,
		callbacks:  callbacks,
		numWorkers: workers,
		stopCh:     make(chan struct{}),
	}
}

// Start begins listening for hook events.
func (m *Manager) Start(ctx context.Context) error {
	// Ensure socket directory exists
	dir := filepath.Dir(m.socketPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create socket dir: %w", err)
	}

	// Remove stale socket
	os.Remove(m.socketPath)

	addr := &net.UnixAddr{Name: m.socketPath, Net: "unixgram"}
	conn, err := net.ListenUnixgram("unixgram", addr)
	if err != nil {
		return fmt.Errorf("listen unix: %w", err)
	}
	m.conn = conn

	// Increase socket receive buffer for high throughput
	conn.SetReadBuffer(4 * 1024 * 1024) // 4MB

	// Allow all users to write to the socket
	os.Chmod(m.socketPath, 0777)

	// Create shared memory control file for on-demand tracing
	ctrl, err := CreateControlFile(dir)
	if err != nil {
		m.logger.Warn("failed to create control file (on-demand tracing unavailable)", zap.Error(err))
	} else {
		m.control = ctrl
		m.logger.Info("control file created", zap.String("path", ctrl.Path()))
	}

	m.logger.Info("hook manager listening",
		zap.String("socket", m.socketPath),
		zap.Int("workers", m.numWorkers),
	)

	// H3 fix: Spawn multiple reader goroutines.
	// DGRAM sockets guarantee message atomicity - each Read() gets one complete datagram.
	// Multiple goroutines can safely read concurrently.
	for i := 0; i < m.numWorkers; i++ {
		m.wg.Add(1)
		go m.readLoop(ctx, i)
	}

	return nil
}

// Stop shuts down the hook manager.
func (m *Manager) Stop() error {
	close(m.stopCh)
	if m.conn != nil {
		m.conn.Close()
	}
	m.wg.Wait()
	if m.control != nil {
		m.control.Close()
		m.control.Remove()
	}
	os.Remove(m.socketPath)
	return nil
}

// EnableTracing activates tracing in all hooked processes via shared memory.
func (m *Manager) EnableTracing() error {
	if m.control == nil {
		return fmt.Errorf("control file not available")
	}
	m.logger.Info("tracing enabled")
	return m.control.Enable()
}

// DisableTracing deactivates tracing. Hooks become pass-through (~1ns overhead).
func (m *Manager) DisableTracing() error {
	if m.control == nil {
		return fmt.Errorf("control file not available")
	}
	m.logger.Info("tracing disabled (dormant)")
	return m.control.Disable()
}

// IsTracingEnabled returns the current tracing state.
func (m *Manager) IsTracingEnabled() bool {
	if m.control == nil {
		return true // no control file = legacy always-active mode
	}
	enabled, _ := m.control.IsEnabled()
	return enabled
}

func (m *Manager) readLoop(ctx context.Context, workerID int) {
	defer m.wg.Done()

	// Each worker gets its own buffer to avoid contention
	buf := make([]byte, HeaderSize+MaxPayload)

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		default:
		}

		n, err := m.conn.Read(buf)
		if err != nil {
			select {
			case <-m.stopCh:
				return
			default:
				m.logger.Debug("read error", zap.Int("worker", workerID), zap.Error(err))
				continue
			}
		}

		if n < HeaderSize {
			m.logger.Debug("message too short", zap.Int("size", n))
			continue
		}

		msg, err := ParseMessage(buf[:n])
		if err != nil {
			m.logger.Debug("parse error", zap.Error(err))
			continue
		}

		m.dispatch(msg)
	}
}

func (m *Manager) dispatch(msg *Message) {
	h := msg.Header

	switch h.MsgType {
	case MsgConnect:
		if m.callbacks.OnConnect != nil && len(msg.Payload) >= 6 {
			remoteAddr := uint32(msg.Payload[0]) |
				uint32(msg.Payload[1])<<8 |
				uint32(msg.Payload[2])<<16 |
				uint32(msg.Payload[3])<<24
			remotePort := uint16(msg.Payload[4]) | uint16(msg.Payload[5])<<8
			// Port is in network byte order, swap
			remotePort = (remotePort >> 8) | (remotePort << 8)
			m.callbacks.OnConnect(h.PID, h.TID, h.FD, remoteAddr, remotePort, h.TimestampNS)
		}

	case MsgDataOut, MsgSSLOut:
		if m.callbacks.OnDataOut != nil && len(msg.Payload) > 0 {
			m.callbacks.OnDataOut(h.PID, h.TID, h.FD, msg.Payload, h.TimestampNS)
		}

	case MsgDataIn, MsgSSLIn:
		if m.callbacks.OnDataIn != nil && len(msg.Payload) > 0 {
			m.callbacks.OnDataIn(h.PID, h.TID, h.FD, msg.Payload, h.TimestampNS)
		}

	case MsgAccept:
		if m.callbacks.OnAccept != nil && len(msg.Payload) >= 6 {
			remoteAddr := uint32(msg.Payload[0]) |
				uint32(msg.Payload[1])<<8 |
				uint32(msg.Payload[2])<<16 |
				uint32(msg.Payload[3])<<24
			remotePort := uint16(msg.Payload[4]) | uint16(msg.Payload[5])<<8
			remotePort = (remotePort >> 8) | (remotePort << 8)
			m.callbacks.OnAccept(h.PID, h.TID, h.FD, remoteAddr, remotePort, h.TimestampNS)
		}

	case MsgClose:
		if m.callbacks.OnClose != nil {
			m.callbacks.OnClose(h.PID, h.TID, h.FD, h.TimestampNS)
		}

	case MsgLogWrite:
		if m.callbacks.OnLogWrite != nil && len(msg.Payload) > 0 {
			m.callbacks.OnLogWrite(h.PID, h.TID, h.FD, msg.Payload, h.TimestampNS)
		}
	}
}
