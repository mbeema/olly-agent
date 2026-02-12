// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package reassembly

import (
	"bytes"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RequestPair represents a matched request and response on a connection.
type RequestPair struct {
	PID        uint32
	TID        uint32
	FD         int32
	RemoteAddr string
	RemotePort uint16
	IsSSL      bool
	Protocol   string

	Request     []byte
	Response    []byte
	RequestTime time.Time
	Duration    time.Duration

	// Inherited trace context from inbound request on same PID+TID.
	// Used for intra-process parent-child linking (e.g., HTTP SERVER → DB CLIENT).
	ParentTraceID  string
	ParentSpanID   string // SERVER span's own spanID (CLIENT uses as parent)
	InjectedSpanID string // sk_msg-injected spanID (CLIENT uses as its own spanID)

	// Direction: 0=outbound (connect), 1=inbound (accept)
	Direction int
}

// streamKey uniquely identifies a stream.
type streamKey struct {
	PID uint32
	FD  int32
}

// streamState tracks per-connection protocol parsing state.
type streamState struct {
	stream     *Stream
	protocol   string
	detected   bool
	reqFramer  *httpFramer // framing state for request direction
	respFramer *httpFramer // framing state for response direction
	lastTID    uint32
	direction  int // 0=outbound, 1=inbound; set by caller
}

// Reassembler manages streams and emits request/response pairs.
// Uses protocol-aware framing to detect message boundaries.
type Reassembler struct {
	mu      sync.RWMutex
	streams map[streamKey]*streamState
	logger  *zap.Logger
	onPair  func(*RequestPair)
}

// NewReassembler creates a new stream reassembler.
func NewReassembler(logger *zap.Logger) *Reassembler {
	return &Reassembler{
		streams: make(map[streamKey]*streamState),
		logger:  logger,
	}
}

// OnPair registers a callback for completed request/response pairs.
func (r *Reassembler) OnPair(fn func(*RequestPair)) {
	r.onPair = fn
}

func (r *Reassembler) getOrCreate(pid uint32, fd int32, remoteAddr string, remotePort uint16) *streamState {
	key := streamKey{PID: pid, FD: fd}

	r.mu.RLock()
	ss, ok := r.streams[key]
	r.mu.RUnlock()

	if ok {
		return ss
	}

	r.mu.Lock()
	if ss, ok = r.streams[key]; ok {
		r.mu.Unlock()
		return ss
	}
	ss = &streamState{
		stream:     NewStream(pid, fd, remoteAddr, remotePort),
		reqFramer:  &httpFramer{},
		respFramer: &httpFramer{},
	}
	r.streams[key] = ss
	r.mu.Unlock()

	return ss
}

// SetDirection sets the connection direction for a stream (0=outbound, 1=inbound).
func (r *Reassembler) SetDirection(pid uint32, fd int32, direction int) {
	key := streamKey{PID: pid, FD: fd}
	r.mu.RLock()
	ss, ok := r.streams[key]
	r.mu.RUnlock()
	if ok {
		ss.direction = direction
	}
}

// AppendSend adds outbound data to the stream.
func (r *Reassembler) AppendSend(pid, tid uint32, fd int32, data []byte, remoteAddr string, remotePort uint16, isSSL bool) {
	ss := r.getOrCreate(pid, fd, remoteAddr, remotePort)
	ss.stream.IsSSL = ss.stream.IsSSL || isSSL
	ss.stream.AppendSend(data)
	ss.lastTID = tid

	r.tryExtractPairs(ss)
}

// AppendRecv adds inbound data to the stream.
func (r *Reassembler) AppendRecv(pid, tid uint32, fd int32, data []byte, remoteAddr string, remotePort uint16, isSSL bool) {
	ss := r.getOrCreate(pid, fd, remoteAddr, remotePort)
	ss.stream.IsSSL = ss.stream.IsSSL || isSSL
	ss.stream.AppendRecv(data)
	ss.lastTID = tid

	r.tryExtractPairs(ss)
}

// tryExtractPairs attempts to extract complete request/response pairs.
// Protocol-aware: uses framing to find message boundaries.
func (r *Reassembler) tryExtractPairs(ss *streamState) {
	s := ss.stream

	for {
		s.mu.Lock()
		sendBuf := s.sendBuf
		recvBuf := s.recvBuf
		s.mu.Unlock()

		if len(sendBuf) == 0 || len(recvBuf) == 0 {
			return
		}

		// Detect protocol on first data
		if !ss.detected {
			ss.protocol = detectProtocol(sendBuf, ss.stream.RemotePort)
			ss.detected = true
			ss.stream.Protocol = ss.protocol
		}

		// Extract one complete request
		reqLen := frameMessage(sendBuf, ss.protocol, true)
		if reqLen <= 0 {
			return // incomplete request
		}

		// Extract one complete response
		respLen := frameMessage(recvBuf, ss.protocol, false)
		if respLen <= 0 {
			return // incomplete response
		}

		// Build pair from exactly one request + one response
		s.mu.Lock()
		pair := &RequestPair{
			PID:         s.PID,
			TID:         ss.lastTID,
			FD:          s.FD,
			RemoteAddr:  s.RemoteAddr,
			RemotePort:  s.RemotePort,
			IsSSL:       s.IsSSL,
			Protocol:    ss.protocol,
			Request:     make([]byte, reqLen),
			Response:    make([]byte, respLen),
			RequestTime: s.lastSend,
			Duration:    s.lastRecv.Sub(s.lastSend),
			Direction:   ss.direction,
		}
		copy(pair.Request, s.sendBuf[:reqLen])
		copy(pair.Response, s.recvBuf[:respLen])

		// Consume exactly what we used
		s.sendBuf = s.sendBuf[reqLen:]
		s.recvBuf = s.recvBuf[respLen:]
		s.mu.Unlock()

		if pair.Duration < 0 {
			pair.Duration = 0
		}

		if r.onPair != nil {
			r.onPair(pair)
		}

		// Loop to handle pipelining: there may be more pairs in the buffers
	}
}

// RemoveStream removes a stream and emits any remaining data as a partial pair.
func (r *Reassembler) RemoveStream(pid uint32, fd int32, tid uint32) {
	key := streamKey{PID: pid, FD: fd}

	r.mu.Lock()
	ss, ok := r.streams[key]
	delete(r.streams, key)
	r.mu.Unlock()

	if !ok {
		return
	}

	s := ss.stream
	if s.HasData() && r.onPair != nil {
		s.mu.Lock()
		pair := &RequestPair{
			PID:         s.PID,
			TID:         tid,
			FD:          s.FD,
			RemoteAddr:  s.RemoteAddr,
			RemotePort:  s.RemotePort,
			IsSSL:       s.IsSSL,
			Protocol:    ss.protocol,
			Request:     make([]byte, len(s.sendBuf)),
			Response:    make([]byte, len(s.recvBuf)),
			RequestTime: s.lastSend,
			Duration:    s.lastRecv.Sub(s.lastSend),
			Direction:   ss.direction,
		}
		copy(pair.Request, s.sendBuf)
		copy(pair.Response, s.recvBuf)
		s.mu.Unlock()

		if pair.Duration < 0 {
			pair.Duration = 0
		}

		r.onPair(pair)
	}
}

// StreamCount returns the number of active streams.
func (r *Reassembler) StreamCount() int {
	r.mu.RLock()
	n := len(r.streams)
	r.mu.RUnlock()
	return n
}

// CleanStale removes streams that have been idle for longer than maxIdle.
func (r *Reassembler) CleanStale(maxIdle time.Duration) int {
	cutoff := time.Now().Add(-maxIdle)
	removed := 0

	r.mu.Lock()
	for key, ss := range r.streams {
		if ss.stream.LastActivity().Before(cutoff) {
			delete(r.streams, key)
			removed++
		}
	}
	r.mu.Unlock()

	return removed
}

/* ─── Protocol-aware message framing ────────────────────────────── */

// frameMessage returns the length of the first complete message in buf,
// or 0 if the message is incomplete, or -1 on error.
func frameMessage(buf []byte, proto string, isRequest bool) int {
	switch proto {
	case "http", "grpc":
		return frameHTTP(buf, isRequest)
	case "postgres":
		return framePostgres(buf)
	case "mysql":
		return frameMySQL(buf)
	case "redis":
		return frameRedis(buf)
	case "mongodb":
		return frameMongoDB(buf)
	case "dns":
		return frameDNS(buf)
	default:
		// Unknown protocol: consume everything available
		return len(buf)
	}
}

// frameHTTP finds the boundary of one complete HTTP message.
// Handles: Content-Length, chunked transfer encoding, and no-body responses.
func frameHTTP(buf []byte, isRequest bool) int {
	// Find end of headers
	headerEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		return 0 // headers incomplete
	}
	headerEnd += 4 // include the \r\n\r\n

	headers := string(buf[:headerEnd])

	// Check for Content-Length
	cl := extractHeaderValue(headers, "content-length")
	if cl != "" {
		contentLen, err := strconv.Atoi(strings.TrimSpace(cl))
		if err != nil || contentLen < 0 {
			return headerEnd // malformed, treat as headers-only
		}
		totalLen := headerEnd + contentLen
		if totalLen > len(buf) {
			return 0 // body incomplete
		}
		return totalLen
	}

	// Check for Transfer-Encoding: chunked
	te := extractHeaderValue(headers, "transfer-encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		return frameChunked(buf, headerEnd)
	}

	// No Content-Length and not chunked:
	// For requests: HEAD, GET, DELETE typically have no body → headers only
	// For responses: 1xx, 204, 304 have no body; otherwise body ends at close
	if isRequest {
		firstLine := headers[:strings.Index(headers, "\r\n")]
		method := strings.Fields(firstLine)
		if len(method) > 0 {
			switch method[0] {
			case "POST", "PUT", "PATCH":
				// These SHOULD have Content-Length. If missing, take headers only
				// (the body will come in a subsequent read)
				return headerEnd
			}
		}
		return headerEnd
	}

	// Response without Content-Length and not chunked
	// Check status code
	firstLine := headers[:strings.Index(headers, "\r\n")]
	parts := strings.Fields(firstLine)
	if len(parts) >= 2 {
		code, _ := strconv.Atoi(parts[1])
		// 1xx, 204, 304 have no body
		if (code >= 100 && code < 200) || code == 204 || code == 304 {
			return headerEnd
		}
	}

	// Response with unknown length: take headers only for now
	// The next recv will bring more data and we'll get it on connection close
	return headerEnd
}

// frameChunked finds the end of chunked transfer encoding.
func frameChunked(buf []byte, bodyStart int) int {
	offset := bodyStart

	for offset < len(buf) {
		// Each chunk: <hex-size>\r\n<data>\r\n
		lineEnd := bytes.Index(buf[offset:], []byte("\r\n"))
		if lineEnd < 0 {
			return 0 // incomplete
		}

		sizeStr := strings.TrimSpace(string(buf[offset : offset+lineEnd]))
		// Strip chunk extensions (;key=value)
		if idx := strings.IndexByte(sizeStr, ';'); idx >= 0 {
			sizeStr = sizeStr[:idx]
		}

		chunkSize, err := strconv.ParseInt(sizeStr, 16, 64)
		if err != nil {
			return offset // malformed, return what we have
		}

		// Move past size line
		offset += lineEnd + 2

		if chunkSize == 0 {
			// Terminal chunk: 0\r\n followed by optional trailers and final \r\n
			trailerEnd := bytes.Index(buf[offset:], []byte("\r\n"))
			if trailerEnd < 0 {
				return 0 // incomplete
			}
			return offset + trailerEnd + 2
		}

		// Skip chunk data + trailing \r\n
		offset += int(chunkSize) + 2
		if offset > len(buf) {
			return 0 // incomplete
		}
	}

	return 0 // incomplete
}

// framePostgres finds the boundary of one PostgreSQL wire message.
func framePostgres(buf []byte) int {
	if len(buf) < 5 {
		return 0
	}

	// First byte is message type, next 4 are length (includes self)
	msgType := buf[0]

	// Startup message has no type byte (starts with length + version)
	if msgType == 0 {
		return len(buf) // consume all for startup
	}

	msgLen := int(buf[1])<<24 | int(buf[2])<<16 | int(buf[3])<<8 | int(buf[4])
	totalLen := 1 + msgLen // type byte + payload (length includes itself)

	if totalLen > len(buf) {
		return 0 // incomplete
	}
	return totalLen
}

// frameMySQL finds the boundary of one MySQL packet.
func frameMySQL(buf []byte) int {
	if len(buf) < 4 {
		return 0
	}

	// MySQL packet: 3-byte length + 1-byte sequence
	pktLen := int(buf[0]) | int(buf[1])<<8 | int(buf[2])<<16
	totalLen := 4 + pktLen

	if totalLen > len(buf) {
		return 0
	}
	return totalLen
}

// frameRedis finds the boundary of one RESP message.
func frameRedis(buf []byte) int {
	if len(buf) < 3 {
		return 0
	}

	switch buf[0] {
	case '+', '-', ':':
		// Simple string, error, integer: ends at \r\n
		end := bytes.Index(buf, []byte("\r\n"))
		if end < 0 {
			return 0
		}
		return end + 2

	case '$':
		// Bulk string: $<len>\r\n<data>\r\n
		lineEnd := bytes.Index(buf, []byte("\r\n"))
		if lineEnd < 0 {
			return 0
		}
		strLen, err := strconv.Atoi(string(buf[1:lineEnd]))
		if err != nil {
			return lineEnd + 2
		}
		if strLen < 0 {
			return lineEnd + 2 // null bulk string
		}
		totalLen := lineEnd + 2 + strLen + 2
		if totalLen > len(buf) {
			return 0
		}
		return totalLen

	case '*':
		// Array: recursively frame each element
		return frameRESPArray(buf)

	default:
		// Inline command
		end := bytes.Index(buf, []byte("\r\n"))
		if end < 0 {
			return 0
		}
		return end + 2
	}
}

func frameRESPArray(buf []byte) int {
	lineEnd := bytes.Index(buf, []byte("\r\n"))
	if lineEnd < 0 {
		return 0
	}

	count, err := strconv.Atoi(string(buf[1:lineEnd]))
	if err != nil || count < 0 {
		return lineEnd + 2
	}

	offset := lineEnd + 2
	for i := 0; i < count; i++ {
		if offset >= len(buf) {
			return 0
		}
		elemLen := frameRedis(buf[offset:])
		if elemLen <= 0 {
			return 0
		}
		offset += elemLen
	}

	return offset
}

// frameMongoDB finds the boundary of one MongoDB wire protocol message.
func frameMongoDB(buf []byte) int {
	if len(buf) < 16 {
		return 0
	}

	// First 4 bytes: message length (little-endian)
	msgLen := int(buf[0]) | int(buf[1])<<8 | int(buf[2])<<16 | int(buf[3])<<24

	if msgLen < 16 || msgLen > 48*1024*1024 {
		return len(buf) // malformed, consume all
	}

	if msgLen > len(buf) {
		return 0
	}
	return msgLen
}

// frameDNS finds the boundary of one DNS message.
func frameDNS(buf []byte) int {
	if len(buf) < 12 {
		return 0
	}
	// DNS over UDP: one message per datagram, consume all
	return len(buf)
}

/* ─── Protocol detection (content-first, port as fallback) ──────── */

func detectProtocol(data []byte, port uint16) string {
	if len(data) < 3 {
		return "unknown"
	}

	// Content-based detection first (port-agnostic)
	s := string(data[:min(len(data), 24)])

	// HTTP/2 preface
	if bytes.HasPrefix(data, []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")) {
		return "grpc" // or http2, but treat as grpc for now
	}

	// HTTP request
	httpMethods := []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT "}
	for _, m := range httpMethods {
		if strings.HasPrefix(s, m) {
			return "http"
		}
	}
	// HTTP response
	if strings.HasPrefix(s, "HTTP/") {
		return "http"
	}

	// PostgreSQL: type byte + 4-byte length
	if len(data) >= 5 {
		if data[0] == 'Q' || data[0] == 'P' || data[0] == 'B' || data[0] == 'E' {
			msgLen := int(data[1])<<24 | int(data[2])<<16 | int(data[3])<<8 | int(data[4])
			if msgLen > 4 && msgLen < 1<<20 {
				return "postgres"
			}
		}
	}

	// MySQL: 3-byte len + seq + command
	if len(data) >= 5 {
		pktLen := int(data[0]) | int(data[1])<<8 | int(data[2])<<16
		if data[3] == 0 && pktLen > 0 && pktLen < 1<<20 {
			cmd := data[4]
			if cmd == 0x03 || cmd == 0x16 || cmd == 0x17 || cmd == 0x0e || cmd == 0x01 || cmd == 0x02 || cmd == 0x0a {
				return "mysql"
			}
		}
	}

	// Redis RESP
	if data[0] == '*' || data[0] == '+' || data[0] == '-' || data[0] == '$' || data[0] == ':' {
		if bytes.Contains(data[:min(len(data), 32)], []byte("\r\n")) {
			return "redis"
		}
	}

	// MongoDB: 4-byte len + 4-byte reqID + 4-byte respTo + 4-byte opCode
	if len(data) >= 16 {
		msgLen := int(data[0]) | int(data[1])<<8 | int(data[2])<<16 | int(data[3])<<24
		opCode := int(data[12]) | int(data[13])<<8 | int(data[14])<<16 | int(data[15])<<24
		if msgLen >= 16 && msgLen < 48*1024*1024 && (opCode == 2013 || opCode == 2004 || opCode == 1) {
			return "mongodb"
		}
	}

	// DNS: 12-byte header
	if len(data) >= 12 {
		flags := uint16(data[2])<<8 | uint16(data[3])
		opcode := (flags >> 11) & 0x0F
		qdCount := uint16(data[4])<<8 | uint16(data[5])
		if opcode <= 2 && qdCount >= 1 && qdCount <= 10 {
			if port == 53 {
				return "dns"
			}
		}
	}

	// Port-based fallback (only if content detection failed)
	switch port {
	case 80, 443, 8080, 8443, 3000, 5000, 8000, 9090:
		return "http"
	case 5432:
		return "postgres"
	case 3306:
		return "mysql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	case 50051:
		return "grpc"
	case 53:
		return "dns"
	}

	return "unknown"
}

// extractHeaderValue finds a header value (case-insensitive name match).
func extractHeaderValue(headers string, name string) string {
	lower := strings.ToLower(headers)
	target := strings.ToLower(name) + ":"
	idx := strings.Index(lower, target)
	if idx < 0 {
		return ""
	}
	start := idx + len(target)
	end := strings.Index(headers[start:], "\r\n")
	if end < 0 {
		return strings.TrimSpace(headers[start:])
	}
	return strings.TrimSpace(headers[start : start+end])
}

// httpFramer tracks HTTP framing state for one direction.
type httpFramer struct {
	// reserved for future use (HTTP/2 stream tracking, etc.)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
