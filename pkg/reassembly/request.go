// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package reassembly

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	// Database name extracted from protocol handshake (PG startup, MySQL COM_INIT_DB)
	DBNamespace string
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
	lastTID    atomic.Uint32 // H2 fix: atomic to prevent data race
	direction  atomic.Int32  // H2b fix: atomic to prevent data race; 0=outbound, 1=inbound

	// PostgreSQL: true after auth handshake is consumed. Before this,
	// all data (startup, SSL negotiation, auth) is discarded to prevent
	// auth messages from contaminating query span pairing.
	pgReady bool

	// MySQL: true after server greeting + auth handshake is consumed.
	// MySQL's handshake is server-initiated (greeting → auth response → OK).
	mysqlReady bool

	// Database name extracted from protocol handshake (propagated to pairs)
	dbNamespace string
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
// H2b fix: uses atomic store for thread safety.
func (r *Reassembler) SetDirection(pid uint32, fd int32, direction int) {
	key := streamKey{PID: pid, FD: fd}
	r.mu.RLock()
	ss, ok := r.streams[key]
	r.mu.RUnlock()
	if ok {
		ss.direction.Store(int32(direction))
	}
}

// AppendSend adds outbound data to the stream.
func (r *Reassembler) AppendSend(pid, tid uint32, fd int32, data []byte, remoteAddr string, remotePort uint16, isSSL bool) {
	ss := r.getOrCreate(pid, fd, remoteAddr, remotePort)
	ss.stream.IsSSL = ss.stream.IsSSL || isSSL
	ss.stream.AppendSend(data)
	ss.lastTID.Store(tid) // H2 fix: atomic store

	r.tryExtractPairs(ss)
}

// AppendRecv adds inbound data to the stream.
func (r *Reassembler) AppendRecv(pid, tid uint32, fd int32, data []byte, remoteAddr string, remotePort uint16, isSSL bool) {
	ss := r.getOrCreate(pid, fd, remoteAddr, remotePort)
	ss.stream.IsSSL = ss.stream.IsSSL || isSSL
	ss.stream.AppendRecv(data)
	// Do NOT update lastTID here. The pair's TID must come from AppendSend
	// (the request direction) because trace context (threadCtx in agent.go)
	// is stored under the request's TID. For Go servers, goroutines migrate
	// between OS threads, so write() (response) often runs on a different
	// TID than read() (request). Using the response TID would cause
	// enrichPairContext to miss the exact match and fall back to PID-only,
	// picking stale context from a previous request's thread.

	r.tryExtractPairs(ss)
}

// tryExtractPairs attempts to extract complete request/response pairs.
// Protocol-aware: uses framing to find message boundaries.
// C1 fix: holds single lock for buffer read, frame computation, and extraction
// to prevent TOCTOU race where concurrent goroutines could consume buffer data
// between frame length computation and data extraction.
func (r *Reassembler) tryExtractPairs(ss *streamState) {
	s := ss.stream

	for {
		s.mu.Lock()

		if len(s.sendBuf) == 0 || len(s.recvBuf) == 0 {
			s.mu.Unlock()
			return
		}

		// Detect protocol on first data
		if !ss.detected {
			ss.protocol = detectProtocol(s.sendBuf, ss.stream.RemotePort)
			// Fallback: for inbound (SERVER) connections, sendBuf starts with the
			// client's first message (e.g., MySQL auth response, seqID=1) which may
			// not match content-based detection. Try recvBuf which has the server's
			// response (e.g., MySQL handshake with protocol version 0x0a).
			if ss.protocol == "unknown" && len(s.recvBuf) > 0 {
				ss.protocol = detectProtocol(s.recvBuf, ss.stream.RemotePort)
			}
			ss.detected = true
			ss.stream.Protocol = ss.protocol
		}

		// PostgreSQL: consume auth handshake before query pairing.
		// PG connections start with SSL negotiation + startup + auth exchange.
		// This data doesn't represent queries and would create noise spans
		// with wrong timestamps. Discard it until the first actual query (Q/P).
		if ss.protocol == "postgres" && !ss.pgReady {
			// Extract database name from PG startup message before discarding
			if ss.dbNamespace == "" {
				ss.dbNamespace = extractPgDatabase(s.sendBuf)
			}
			queryStart := findPgQueryStart(s.sendBuf)
			if queryStart < 0 {
				// No query found yet — discard all auth data
				s.sendBuf = s.sendBuf[:0]
				s.recvBuf = s.recvBuf[:0]
				s.mu.Unlock()
				return
			}
			// Discard auth messages before the query in both buffers
			s.sendBuf = s.sendBuf[queryStart:]
			skipLen := skipPgAuthRecv(s.recvBuf)
			s.recvBuf = s.recvBuf[skipLen:]
			ss.pgReady = true
			// Fall through to normal pair extraction with clean buffers
			if len(s.sendBuf) == 0 || len(s.recvBuf) == 0 {
				s.mu.Unlock()
				return
			}
		}

		// MySQL: consume server greeting + auth handshake before query pairing.
		// MySQL handshake is server-initiated: greeting → client auth → OK/ERR.
		// Discard until the first COM_* command (seq=0 + valid command byte).
		if ss.protocol == "mysql" && !ss.mysqlReady {
			// Extract database name from MySQL handshake response
			if ss.dbNamespace == "" {
				ss.dbNamespace = extractMySQLDatabase(s.sendBuf)
			}
			queryStart := findMySQLQueryStart(s.sendBuf)
			if queryStart < 0 {
				s.sendBuf = s.sendBuf[:0]
				s.recvBuf = s.recvBuf[:0]
				s.mu.Unlock()
				return
			}
			s.sendBuf = s.sendBuf[queryStart:]
			skipLen := skipMySQLHandshake(s.recvBuf)
			s.recvBuf = s.recvBuf[skipLen:]
			ss.mysqlReady = true
			if len(s.sendBuf) == 0 || len(s.recvBuf) == 0 {
				s.mu.Unlock()
				return
			}
		}

		// MySQL: skip commands that have no server response (COM_STMT_CLOSE,
		// COM_QUIT). Without this, the no-response command in sendBuf gets
		// paired with the NEXT query's response in recvBuf, causing cascading
		// misalignment that loses most MySQL spans. Go's database/sql always
		// sends COM_STMT_CLOSE after each prepared statement execution.
		if ss.protocol == "mysql" && len(s.sendBuf) >= 5 {
			cmd := s.sendBuf[4]
			if cmd == 0x19 || cmd == 0x01 { // COM_STMT_CLOSE or COM_QUIT
				pktLen := int(s.sendBuf[0]) | int(s.sendBuf[1])<<8 | int(s.sendBuf[2])<<16
				totalLen := 4 + pktLen
				if totalLen > 0 && totalLen <= len(s.sendBuf) {
					s.sendBuf = s.sendBuf[totalLen:]
					s.mu.Unlock()
					r.tryExtractPairs(ss)
					return
				}
			}
		}

		// Extract one complete request
		reqLen := frameMessage(s.sendBuf, ss.protocol, true)
		if reqLen <= 0 {
			s.mu.Unlock()
			return // incomplete request
		}

		// Extract one complete response
		respLen := frameMessage(s.recvBuf, ss.protocol, false)
		if respLen <= 0 {
			s.mu.Unlock()
			return // incomplete response
		}

		// Build pair from exactly one request + one response.
		// Duration fix: guard against zero lastSend (no AppendSend happened).
		// time.Since(time.Time{}) saturates to math.MaxInt64 (~292 years).
		reqTime := s.lastSend
		if reqTime.IsZero() {
			reqTime = s.lastRecv
		}
		duration := s.lastRecv.Sub(reqTime)
		if duration <= 0 {
			duration = time.Since(reqTime)
		}
		if reqTime.IsZero() {
			reqTime = time.Now()
			duration = 0
		}
		pair := &RequestPair{
			PID:         s.PID,
			TID:         ss.lastTID.Load(),
			FD:          s.FD,
			RemoteAddr:  s.RemoteAddr,
			RemotePort:  s.RemotePort,
			IsSSL:       s.IsSSL,
			Protocol:    ss.protocol,
			Request:     make([]byte, reqLen),
			Response:    make([]byte, respLen),
			RequestTime: reqTime,
			Duration:    duration,
			Direction:   int(ss.direction.Load()),
			DBNamespace: ss.dbNamespace,
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

		// PG cleanup on close: skip noise spans from auth or admin messages.
		if ss.protocol == "postgres" {
			if !ss.pgReady {
				queryStart := findPgQueryStart(s.sendBuf)
				if queryStart < 0 {
					s.mu.Unlock()
					return
				}
				s.sendBuf = s.sendBuf[queryStart:]
				skipLen := skipPgAuthRecv(s.recvBuf)
				s.recvBuf = s.recvBuf[skipLen:]
				ss.pgReady = true
				if len(s.sendBuf) == 0 {
					s.mu.Unlock()
					return
				}
			} else if len(s.sendBuf) > 0 && s.sendBuf[0] != 'Q' && s.sendBuf[0] != 'P' && s.sendBuf[0] != 'B' && s.sendBuf[0] != 'E' {
				// Post-auth leftovers (Terminate 'X', etc.) — not query data
				s.mu.Unlock()
				return
			}
		}

		// MySQL cleanup on close: skip handshake or QUIT leftovers.
		if ss.protocol == "mysql" {
			if !ss.mysqlReady {
				queryStart := findMySQLQueryStart(s.sendBuf)
				if queryStart < 0 {
					s.mu.Unlock()
					return
				}
				s.sendBuf = s.sendBuf[queryStart:]
				skipLen := skipMySQLHandshake(s.recvBuf)
				s.recvBuf = s.recvBuf[skipLen:]
				ss.mysqlReady = true
				if len(s.sendBuf) == 0 {
					s.mu.Unlock()
					return
				}
			} else if len(s.sendBuf) >= 5 {
				cmd := s.sendBuf[4]
				if cmd == 0x01 { // COM_QUIT — not useful
					s.mu.Unlock()
					return
				}
			}
		}

		// Guard against zero lastSend (only recvBuf had data).
		reqTime := s.lastSend
		if reqTime.IsZero() {
			reqTime = s.lastRecv
		}
		duration := s.lastRecv.Sub(reqTime)
		if duration <= 0 {
			duration = time.Since(reqTime)
		}
		if reqTime.IsZero() {
			reqTime = time.Now()
			duration = 0
		}
		// Use lastTID (set by AppendSend = request direction) instead of the
		// close event's tid. The close() syscall may execute on a different OS
		// thread than the read() syscall (goroutine migration in Go servers).
		// threadCtx in agent.go is keyed by the read event's TID, so the pair
		// must use that TID for enrichPairContext to find the correct context.
		pairTID := ss.lastTID.Load()
		if pairTID == 0 {
			pairTID = tid // fallback if no data was sent
		}
		pair := &RequestPair{
			PID:         s.PID,
			TID:         pairTID,
			FD:          s.FD,
			RemoteAddr:  s.RemoteAddr,
			RemotePort:  s.RemotePort,
			IsSSL:       s.IsSSL,
			Protocol:    ss.protocol,
			Request:     make([]byte, len(s.sendBuf)),
			Response:    make([]byte, len(s.recvBuf)),
			RequestTime: reqTime,
			Duration:    duration,
			Direction:   int(ss.direction.Load()),
			DBNamespace: ss.dbNamespace,
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

	// Collect stale streams with data so we can emit pairs outside the lock.
	type staleEntry struct {
		key streamKey
		ss  *streamState
	}
	var stale []staleEntry

	r.mu.Lock()
	for key, ss := range r.streams {
		if ss.stream.LastActivity().Before(cutoff) {
			delete(r.streams, key)
			removed++
			if ss.stream.HasData() && r.onPair != nil {
				stale = append(stale, staleEntry{key, ss})
			}
		}
	}
	r.mu.Unlock()

	// Emit pairs from stale streams that had data (e.g., SSL connections
	// where no CLOSE event was received from BPF).
	for _, e := range stale {
		s := e.ss.stream
		s.mu.Lock()
		// Guard against zero lastSend (stale stream with only recv data).
		reqTime := s.lastSend
		if reqTime.IsZero() {
			reqTime = s.lastRecv
		}
		duration := s.lastRecv.Sub(reqTime)
		if duration <= 0 {
			duration = time.Since(reqTime)
		}
		if reqTime.IsZero() {
			reqTime = time.Now()
			duration = 0
		}
		pairTID := e.ss.lastTID.Load()
		pair := &RequestPair{
			PID:         s.PID,
			TID:         pairTID,
			FD:          s.FD,
			RemoteAddr:  s.RemoteAddr,
			RemotePort:  s.RemotePort,
			IsSSL:       s.IsSSL,
			Protocol:    e.ss.protocol,
			Request:     make([]byte, len(s.sendBuf)),
			Response:    make([]byte, len(s.recvBuf)),
			RequestTime: reqTime,
			Duration:    duration,
			Direction:   int(e.ss.direction.Load()),
			DBNamespace: e.ss.dbNamespace,
		}
		copy(pair.Request, s.sendBuf)
		copy(pair.Response, s.recvBuf)
		s.mu.Unlock()

		if pair.Duration < 0 {
			pair.Duration = 0
		}
		r.onPair(pair)
	}

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
		return framePostgres(buf, isRequest)
	case "mysql":
		if isRequest {
			return frameMySQL(buf)
		}
		return frameMySQLResponse(buf)
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
		if err != nil || contentLen <= 0 || contentLen > MaxBufferSize {
			return headerEnd // malformed or out of range, treat as headers-only
		}
		totalLen := headerEnd + contentLen
		if totalLen < headerEnd {
			return headerEnd // overflow protection
		}
		if totalLen > len(buf) {
			// eBPF truncation: each read/write syscall captures at most
			// MAX_CAPTURE (256) bytes. On keep-alive connections, if the
			// response body exceeds MAX_CAPTURE, the body data beyond one
			// capture is invisible. Subsequent buffer growth comes from
			// NEW HTTP messages, not the truncated body. If we've already
			// accumulated more than headerEnd+MAX_CAPTURE of data and CL
			// still isn't satisfied, emit headers-only to unblock the stream.
			if !isRequest && contentLen > ebpfMaxCapture && len(buf) > headerEnd+ebpfMaxCapture {
				return headerEnd
			}
			return 0 // body incomplete, wait for more data
		}
		return totalLen
	}

	// Check for Transfer-Encoding: chunked
	te := extractHeaderValue(headers, "transfer-encoding")
	if strings.Contains(strings.ToLower(te), "chunked") {
		n := frameChunked(buf, headerEnd)
		if n == 0 && !isRequest && len(buf) > headerEnd+ebpfMaxCapture {
			// eBPF truncation: chunk terminator 0\r\n\r\n is beyond
			// MAX_CAPTURE. Return headers-only to unblock the stream.
			return headerEnd
		}
		return n
	}

	// No Content-Length and not chunked:
	// For requests: HEAD, GET, DELETE typically have no body → headers only
	// For responses: 1xx, 204, 304 have no body; otherwise body ends at close
	if isRequest {
		idx := strings.Index(headers, "\r\n")
		if idx < 0 {
			return headerEnd
		}
		firstLine := headers[:idx]
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
	idx := strings.Index(headers, "\r\n")
	if idx < 0 {
		return headerEnd
	}
	firstLine := headers[:idx]
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

		if chunkSize < 0 || chunkSize > int64(len(buf)-offset) {
			return 0 // invalid chunk size
		}

		// Skip chunk data + trailing \r\n
		offset += int(chunkSize) + 2
		if offset > len(buf) {
			return 0 // incomplete
		}
	}

	return 0 // incomplete
}

// framePostgres finds the boundary of a PostgreSQL message batch.
// PG uses multi-message sequences: a request may be P+B+D+E+S (extended query)
// and a response is all messages through ReadyForQuery ('Z').
// Batch-aware framing prevents auth handshake messages from being mis-paired
// with actual query data.
func framePostgres(buf []byte, isRequest bool) int {
	if len(buf) < 4 {
		return 0
	}

	if isRequest {
		return framePostgresRequest(buf)
	}
	return framePostgresResponse(buf)
}

// framePostgresRequest frames one client-side PG message batch.
// - Startup message (buf[0]==0): consume the startup plus any subsequent
//   non-query auth messages (e.g., PasswordMessage 'p'), so the entire
//   auth handshake request side is one batch.
// - Simple Query 'Q': standalone, one message.
// - Extended Query (starts with 'P' or 'B'): consume through Sync 'S'.
// - Other non-query messages: consume until next query-start or buffer end.
func framePostgresRequest(buf []byte) int {
	// Startup message: first byte is 0x00 (high byte of int32 length).
	// Format: length(4) + version(4) + params... + \x00
	if buf[0] == 0 {
		if len(buf) < 8 {
			return 0
		}
		msgLen := int(binary.BigEndian.Uint32(buf[0:4]))
		if msgLen < 8 || msgLen > 1024 {
			return len(buf) // malformed, consume all
		}
		if msgLen > len(buf) {
			return 0 // incomplete
		}
		// Consume startup, then continue consuming non-query auth messages
		// (PasswordMessage 'p', SASLInitialResponse, etc.)
		offset := msgLen
		for offset+5 <= len(buf) {
			mt := buf[offset]
			// Stop before query messages — they belong to the next batch
			if mt == 'Q' || mt == 'P' {
				break
			}
			ml := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
			if ml < 4 || offset+1+ml > len(buf) {
				break
			}
			offset += 1 + ml
		}
		return offset
	}

	if len(buf) < 5 {
		return 0
	}

	// Query messages: consume through the batch boundary
	isQueryStart := buf[0] == 'Q' || buf[0] == 'P' || buf[0] == 'B' || buf[0] == 'E'

	offset := 0
	for offset+5 <= len(buf) {
		mt := buf[offset]
		ml := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
		if ml < 4 || offset+1+ml > len(buf) {
			if !isQueryStart && offset > 0 {
				return offset // return auth messages consumed so far
			}
			return 0 // incomplete
		}
		offset += 1 + ml

		if isQueryStart {
			// Simple Query: standalone message, return immediately
			if mt == 'Q' {
				return offset
			}
			// Sync: end of extended query batch (S with length exactly 4)
			if mt == 'S' && ml == 4 {
				return offset
			}
		} else {
			// Non-query messages (auth leftovers): stop before next query start
			if offset < len(buf) && (buf[offset] == 'Q' || buf[offset] == 'P') {
				return offset
			}
		}
	}

	// Consumed all complete messages but no boundary found
	if !isQueryStart && offset > 0 {
		return offset // return non-query messages consumed
	}
	return 0
}

// framePostgresResponse frames one server-side PG message batch.
// Ideal boundary is ReadyForQuery ('Z'), sent after auth and each query.
// Fallbacks handle eBPF's MAX_CAPTURE=256 truncating long messages:
//   - CommandComplete ('C') or ErrorResponse ('E'): query response done
//   - All auth messages (R/S/K): auth batch with truncated Z
func framePostgresResponse(buf []byte) int {
	if len(buf) < 5 {
		return 0
	}

	offset := 0
	lastCmdOrErr := 0
	allAuth := true

	for offset+5 <= len(buf) {
		mt := buf[offset]
		ml := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
		if ml < 4 || offset+1+ml > len(buf) {
			break // incomplete message
		}
		offset += 1 + ml

		// ReadyForQuery: ideal response boundary
		if mt == 'Z' {
			return offset
		}
		// Track CommandComplete/ErrorResponse as fallback boundary
		if mt == 'C' || mt == 'E' {
			lastCmdOrErr = offset
		}
		// Auth messages: R (Authentication*), S (ParameterStatus), K (BackendKeyData)
		if mt != 'R' && mt != 'S' && mt != 'K' {
			allAuth = false
		}
	}

	// No Z found. Fallback 1: query response has C/E (Z truncated by eBPF)
	if lastCmdOrErr > 0 {
		return lastCmdOrErr
	}
	// Fallback 2: all auth messages (Z truncated during handshake)
	if allAuth && offset > 0 {
		return offset
	}
	return 0 // incomplete, wait for more data
}

// findPgQueryStart scans a PG send buffer for the first query message (Q or P),
// skipping startup messages (length+version format) and auth messages (p, etc.).
// Returns the byte offset where the query starts, or -1 if no query found yet.
func findPgQueryStart(buf []byte) int {
	offset := 0
	for offset < len(buf) {
		// Query message: Simple Query 'Q' or Parse 'P' (extended query start)
		if buf[offset] == 'Q' || buf[offset] == 'P' {
			if offset+5 <= len(buf) {
				ml := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
				if ml >= 4 && ml < 1<<20 {
					return offset
				}
			}
			return -1 // looks like a query but incomplete
		}

		// Startup/SSLRequest message: starts with 0x00 (high byte of int32 length)
		if buf[offset] == 0 {
			if offset+4 > len(buf) {
				return -1 // incomplete
			}
			msgLen := int(binary.BigEndian.Uint32(buf[offset : offset+4]))
			if msgLen < 8 || msgLen > 1024 {
				offset++
				continue // skip garbage byte
			}
			if offset+msgLen > len(buf) {
				return -1 // incomplete
			}
			offset += msgLen
			continue
		}

		// Standard PG message (password 'p', SASL, etc.): type + 4-byte length
		if offset+5 > len(buf) {
			return -1 // incomplete
		}
		ml := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
		if ml < 4 || offset+1+ml > len(buf) {
			return -1 // incomplete
		}
		offset += 1 + ml
	}
	return -1 // no query found
}

// skipPgAuthRecv consumes auth-phase response messages from the front of a PG
// recv buffer: SSL negotiation byte ('N'/'S'), Authentication ('R'),
// ParameterStatus ('S'), BackendKeyData ('K'), ReadyForQuery ('Z'),
// NoticeResponse ('N').
// Returns the number of bytes to skip.
func skipPgAuthRecv(buf []byte) int {
	offset := 0

	// Handle potential single-byte SSL negotiation response ('N'=no SSL, 'S'=SSL).
	// This only appears as the very first response byte before any PG messages.
	// Distinguish from PG messages by checking if it has a valid length field.
	if offset < len(buf) && (buf[offset] == 'N' || buf[offset] == 'S') {
		isSSLByte := true
		if offset+5 <= len(buf) {
			ml := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
			if ml >= 4 && offset+1+ml <= len(buf) {
				isSSLByte = false // valid PG message, not a single SSL byte
			}
		}
		if isSSLByte {
			offset++ // consume single SSL negotiation byte
		}
	}

	// Consume standard PG auth-phase messages (type + 4-byte length).
	for offset+5 <= len(buf) {
		b := buf[offset]
		// Auth messages: R (Authentication*), S (ParameterStatus),
		// K (BackendKeyData), Z (ReadyForQuery), N (NoticeResponse)
		if b != 'R' && b != 'S' && b != 'K' && b != 'Z' && b != 'N' {
			break // non-auth message — query response starts here
		}
		ml := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
		if ml < 4 || offset+1+ml > len(buf) {
			break // incomplete message
		}
		offset += 1 + ml
	}

	return offset
}

// findMySQLQueryStart scans a MySQL send buffer for the first COM_* command
// packet (seq=0 + valid command byte), skipping auth handshake packets.
// Returns the byte offset where the command starts, or -1 if not found.
func findMySQLQueryStart(buf []byte) int {
	offset := 0
	for offset+5 <= len(buf) {
		pktLen := int(buf[offset]) | int(buf[offset+1])<<8 | int(buf[offset+2])<<16
		totalLen := 4 + pktLen
		if pktLen <= 0 || totalLen > len(buf) {
			return -1 // incomplete
		}
		seqID := buf[offset+3]
		// COM_* commands always start a new sequence (seq=0)
		if seqID == 0 && pktLen >= 1 {
			cmd := buf[offset+4]
			if cmd == 0x03 || cmd == 0x16 || cmd == 0x17 || cmd == 0x19 ||
				cmd == 0x02 || cmd == 0x0e || cmd == 0x01 || cmd == 0x0a {
				return offset
			}
		}
		offset += totalLen
	}
	return -1
}

// skipMySQLHandshake consumes MySQL handshake response packets from recvBuf.
// Uses sequence numbers to distinguish auth-phase packets from command responses:
//   - Server greeting: seq=0, payload[0]=0x0a (consumed)
//   - Auth OK/ERR/AuthSwitch: seq >= 2 (consumed — part of auth sequence)
//   - Command response (e.g., COM_PING OK): seq=0 (NOT consumed — new command)
//
// Without seq-number tracking, this function greedily consumed ALL OK (0x00)
// packets, eating COM_PING and even query responses from the connection pool's
// startup Ping(). That caused cascading misalignment and lost most MySQL spans.
func skipMySQLHandshake(buf []byte) int {
	offset := 0
	sawGreeting := false
	for offset+5 <= len(buf) {
		pktLen := int(buf[offset]) | int(buf[offset+1])<<8 | int(buf[offset+2])<<16
		totalLen := 4 + pktLen
		if pktLen <= 0 || totalLen > len(buf) {
			break
		}
		seqID := buf[offset+3]
		payloadType := buf[offset+4]

		if !sawGreeting {
			// First packet must be server greeting (0x0a, seq=0)
			if payloadType == 0x0a && seqID == 0 {
				sawGreeting = true
				offset += totalLen
				continue
			}
			break // not a greeting — can't skip anything
		}

		// After greeting: consume auth-phase responses (seq >= 2).
		// MySQL auth: greeting(seq=0) → client_auth(seq=1) → OK/ERR(seq=2)
		// AuthSwitch: → switch_req(seq=2) → client_data(seq=3) → OK(seq=4)
		// All server auth responses have seq >= 2 because client sends seq=1.
		// Command responses (e.g., COM_PING OK) start at seq=1, so seq < 2.
		if seqID >= 2 {
			offset += totalLen
			continue
		}

		// seq < 2 after greeting = command response (COM_PING OK, query result)
		break
	}
	return offset
}

// extractPgDatabase extracts the database name from a PostgreSQL startup message.
// Startup format: length(4) + version(4) + key\0value\0...key\0value\0\0
func extractPgDatabase(buf []byte) string {
	offset := 0
	for offset < len(buf) {
		// Startup message starts with 0x00 (high byte of int32 length)
		if buf[offset] != 0 {
			// Skip standard PG messages (type + length)
			if offset+5 <= len(buf) {
				ml := int(binary.BigEndian.Uint32(buf[offset+1 : offset+5]))
				if ml >= 4 && offset+1+ml <= len(buf) {
					offset += 1 + ml
					continue
				}
			}
			break
		}
		if offset+8 > len(buf) {
			break
		}
		msgLen := int(binary.BigEndian.Uint32(buf[offset : offset+4]))
		version := binary.BigEndian.Uint32(buf[offset+4 : offset+8])
		if version != 0x00030000 || msgLen < 8 || msgLen > 1024 {
			break
		}
		if offset+msgLen > len(buf) {
			break
		}
		// Parse key=value pairs
		pos := offset + 8
		end := offset + msgLen
		for pos < end {
			// Read key
			keyEnd := pos
			for keyEnd < end && buf[keyEnd] != 0 {
				keyEnd++
			}
			if keyEnd >= end {
				break
			}
			key := string(buf[pos:keyEnd])
			pos = keyEnd + 1
			if key == "" {
				break // end of params
			}
			// Read value
			valEnd := pos
			for valEnd < end && buf[valEnd] != 0 {
				valEnd++
			}
			val := string(buf[pos:valEnd])
			pos = valEnd + 1
			if key == "database" {
				return val
			}
		}
		break
	}
	return ""
}

// extractMySQLDatabase extracts the database name from a MySQL client handshake response.
// The auth response packet (seq=1) contains: capabilities + user + auth + database.
// Go's mysql driver sends the database in the initial auth packet.
func extractMySQLDatabase(buf []byte) string {
	offset := 0
	for offset+5 <= len(buf) {
		pktLen := int(buf[offset]) | int(buf[offset+1])<<8 | int(buf[offset+2])<<16
		totalLen := 4 + pktLen
		if pktLen <= 0 || totalLen > len(buf) {
			break
		}
		seqID := buf[offset+3]
		// Client auth response is seq=1 (reply to server greeting seq=0)
		if seqID == 1 && pktLen > 32 {
			payload := buf[offset+4 : offset+totalLen]
			// MySQL 4.1+ auth response:
			// capabilities(4) + max_packet(4) + charset(1) + reserved(23) + user\0 + auth_len + auth + database\0
			if len(payload) < 32 {
				break
			}
			caps := uint32(payload[0]) | uint32(payload[1])<<8 | uint32(payload[2])<<16 | uint32(payload[3])<<24
			// CLIENT_CONNECT_WITH_DB flag = 0x08
			if caps&0x08 == 0 {
				break // no database in this packet
			}
			// Skip to user field (after 32 bytes of fixed header)
			pos := 32
			// Skip user (null-terminated)
			for pos < len(payload) && payload[pos] != 0 {
				pos++
			}
			pos++ // skip null
			if pos >= len(payload) {
				break
			}
			// Skip auth data
			if caps&0x00200000 != 0 { // CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
				authLen := int(payload[pos])
				pos += 1 + authLen
			} else if caps&0x00008000 != 0 { // CLIENT_SECURE_CONNECTION
				authLen := int(payload[pos])
				pos += 1 + authLen
			} else {
				// Old-style: null-terminated
				for pos < len(payload) && payload[pos] != 0 {
					pos++
				}
				pos++
			}
			if pos >= len(payload) {
				break
			}
			// Database name (null-terminated)
			dbEnd := pos
			for dbEnd < len(payload) && payload[dbEnd] != 0 {
				dbEnd++
			}
			if dbEnd > pos {
				return string(payload[pos:dbEnd])
			}
		}
		offset += totalLen
	}
	return ""
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

// frameMySQLResponse frames a complete MySQL response, which may span multiple
// packets (result sets: column_count + col_defs + EOF + rows + EOF).
// Consumes consecutive packets where the sequence number increments.
// A seq break (next command's response starting at seq=1) stops consumption.
//
// eBPF captures only 256 bytes per read() syscall, so MySQL result sets are
// often truncated mid-packet. If we've consumed at least one complete packet
// and then encounter an incomplete trailing packet, we consume ALL remaining
// bytes to prevent the partial data from corrupting the next response's framing.
func frameMySQLResponse(buf []byte) int {
	if len(buf) < 5 {
		return 0
	}

	offset := 0
	expectedSeq := byte(0) // will be set from first packet
	first := true

	for offset+4 <= len(buf) {
		pktLen := int(buf[offset]) | int(buf[offset+1])<<8 | int(buf[offset+2])<<16
		totalLen := 4 + pktLen
		if pktLen <= 0 || offset+totalLen > len(buf) {
			if !first {
				// Incomplete trailing packet in a multi-packet response.
				// eBPF truncated the capture at 256 bytes. Consume all
				// remaining data to prevent it from corrupting the next
				// response's framing.
				return len(buf)
			}
			return 0 // truly incomplete first packet — wait for more data
		}

		seq := buf[offset+3]
		if first {
			expectedSeq = seq + 1 // accept whatever seq the first packet has
			first = false
		} else if seq != expectedSeq {
			break // seq gap = start of a new command's response
		} else {
			expectedSeq = seq + 1
		}

		offset += totalLen
	}

	return offset
}

const maxRedisDepth = 32

// frameRedis finds the boundary of one RESP message.
func frameRedis(buf []byte) int {
	return frameRedisWithDepth(buf, 0)
}

func frameRedisWithDepth(buf []byte, depth int) int {
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
		return frameRESPArrayWithDepth(buf, depth)

	default:
		// Inline command
		end := bytes.Index(buf, []byte("\r\n"))
		if end < 0 {
			return 0
		}
		return end + 2
	}
}

func frameRESPArrayWithDepth(buf []byte, depth int) int {
	if depth > maxRedisDepth {
		return 0
	}

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
		elemLen := frameRedisWithDepth(buf[offset:], depth+1)
		if elemLen <= 0 {
			return 0
		}
		offset += elemLen
	}

	return offset
}

// ebpfMaxCapture is the maximum bytes captured per eBPF event (MAX_CAPTURE in olly.bpf.c).
// MongoDB/MySQL messages larger than this are truncated in the ring buffer.
const ebpfMaxCapture = 256

// frameMongoDB finds the boundary of one MongoDB wire protocol message.
// Handles eBPF truncation: when msgLen > buffer but the message was truncated
// by MAX_CAPTURE, uses the available data rather than waiting forever.
func frameMongoDB(buf []byte) int {
	if len(buf) < 16 {
		return 0
	}

	// First 4 bytes: message length (little-endian)
	msgLen := int(buf[0]) | int(buf[1])<<8 | int(buf[2])<<16 | int(buf[3])<<24

	if msgLen < 16 || msgLen > 48*1024*1024 {
		return len(buf) // malformed, consume all
	}

	if msgLen <= len(buf) {
		return msgLen // complete message
	}

	// msgLen > len(buf): message may be truncated by eBPF MAX_CAPTURE.
	// Each sendto() sends one MongoDB message; eBPF captures up to 256 bytes.
	// If msgLen exceeds MAX_CAPTURE, we'll never get the rest — use what we have.
	// Verify with opCode check to avoid consuming garbage.
	if msgLen > ebpfMaxCapture && len(buf) >= 21 {
		opCode := int(buf[12]) | int(buf[13])<<8 | int(buf[14])<<16 | int(buf[15])<<24
		if opCode == 2013 || opCode == 2004 || opCode == 1 {
			// Truncated eBPF event. Consume up to MAX_CAPTURE bytes for this message.
			// If buffer has more (from subsequent events), find the boundary.
			if len(buf) <= ebpfMaxCapture {
				return len(buf)
			}
			// Multiple events in buffer: scan for next valid MongoDB header
			// starting near MAX_CAPTURE boundary.
			for i := ebpfMaxCapture - 4; i <= ebpfMaxCapture+4 && i+16 <= len(buf); i++ {
				if i < 16 {
					continue
				}
				nl := int(buf[i]) | int(buf[i+1])<<8 | int(buf[i+2])<<16 | int(buf[i+3])<<24
				if nl < 16 || nl > 48*1024*1024 {
					continue
				}
				no := int(buf[i+12]) | int(buf[i+13])<<8 | int(buf[i+14])<<16 | int(buf[i+15])<<24
				if no == 2013 || no == 2004 || no == 1 {
					return i
				}
			}
			// No next header found; use MAX_CAPTURE as boundary
			if len(buf) >= ebpfMaxCapture {
				return ebpfMaxCapture
			}
			return len(buf)
		}
	}

	return 0 // wait for more data
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
			msgLen := int(binary.BigEndian.Uint32(data[1:5]))
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
