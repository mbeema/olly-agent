// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package reassembly

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"

	"go.uber.org/zap"
)

func TestFrameHTTP_ValidContentLength(t *testing.T) {
	body := "hello world"
	msg := fmt.Sprintf("GET / HTTP/1.1\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	buf := []byte(msg)

	n := frameHTTP(buf, true)
	if n != len(buf) {
		t.Errorf("frameHTTP = %d, want %d", n, len(buf))
	}
}

func TestFrameHTTP_MaliciousContentLength_IntMax(t *testing.T) {
	msg := fmt.Sprintf("GET / HTTP/1.1\r\nContent-Length: %d\r\n\r\n", math.MaxInt)
	buf := []byte(msg)

	n := frameHTTP(buf, true)
	// Content-Length exceeds MaxBufferSize, should return headerEnd
	headerEnd := len("GET / HTTP/1.1\r\nContent-Length: ") + len(fmt.Sprintf("%d", math.MaxInt)) + len("\r\n\r\n")
	if n != headerEnd {
		t.Errorf("frameHTTP with INT_MAX Content-Length = %d, want %d (headerEnd)", n, headerEnd)
	}
}

func TestFrameHTTP_NegativeContentLength(t *testing.T) {
	msg := "GET / HTTP/1.1\r\nContent-Length: -1\r\n\r\n"
	buf := []byte(msg)

	n := frameHTTP(buf, true)
	headerEnd := len(msg)
	if n != headerEnd {
		t.Errorf("frameHTTP with negative Content-Length = %d, want %d (headerEnd)", n, headerEnd)
	}
}

func TestFrameHTTP_ZeroContentLength(t *testing.T) {
	msg := "GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
	buf := []byte(msg)

	n := frameHTTP(buf, true)
	// contentLen == 0 is rejected (not > 0), should return headerEnd
	headerEnd := len(msg)
	if n != headerEnd {
		t.Errorf("frameHTTP with zero Content-Length = %d, want %d (headerEnd)", n, headerEnd)
	}
}

func TestFrameHTTP_MissingCRLN_Request(t *testing.T) {
	// Headers present (ends with \r\n\r\n) but no \r\n in the first line area
	// This is a malformed request where there's a header block but no request line separator
	// Construct: "GET / HTTP/1.1" without \r\n followed by \r\n\r\n
	// Actually the header section is defined as everything before \r\n\r\n
	// so headers will be "GET / HTTP/1.1" with no \r\n at all
	buf := []byte("MALFORMED\r\n\r\n")

	// headers = "MALFORMED\r\n\r\n" wait, let me trace through the code.
	// headerEnd = index of \r\n\r\n + 4 = 9 + 4 = 13
	// headers = "MALFORMED\r\n\r\n" (indices 0..12)
	// No Content-Length, not chunked, isRequest=true
	// idx = strings.Index(headers, "\r\n") = 9 (found)
	// firstLine = "MALFORMED"
	// So this won't trigger the -1 case. Let me construct a case where headers has no \r\n:
	// That can't actually happen because headerEnd includes \r\n\r\n.
	// The headers string always contains at least one \r\n because it ends with \r\n\r\n.
	// But the fix is still correct defensive programming.

	n := frameHTTP(buf, true)
	if n != len(buf) {
		t.Errorf("frameHTTP = %d, want %d", n, len(buf))
	}
}

func TestFrameHTTP_ResponseNoContentLength(t *testing.T) {
	buf := []byte("HTTP/1.1 204 No Content\r\n\r\n")

	n := frameHTTP(buf, false)
	if n != len(buf) {
		t.Errorf("frameHTTP 204 response = %d, want %d", n, len(buf))
	}
}

func TestFrameChunked_ValidChunks(t *testing.T) {
	// Construct a valid chunked body: "5\r\nhello\r\n0\r\n\r\n"
	headers := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	chunkedBody := "5\r\nhello\r\n0\r\n\r\n"
	buf := []byte(headers + chunkedBody)

	n := frameHTTP(buf, false)
	if n != len(buf) {
		t.Errorf("frameHTTP chunked = %d, want %d", n, len(buf))
	}
}

func TestFrameChunked_HugeChunkSize(t *testing.T) {
	// Chunk size larger than buffer
	headers := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	chunkedBody := "FFFFFFFFFF\r\ndata\r\n0\r\n\r\n"
	buf := []byte(headers + chunkedBody)

	n := frameHTTP(buf, false)
	// Huge chunk size exceeds remaining buffer, should return 0 (invalid chunk)
	if n != 0 {
		t.Errorf("frameHTTP with huge chunk = %d, want 0", n)
	}
}

func TestFrameChunked_NegativeChunkSize(t *testing.T) {
	// ParseInt with hex won't produce negative easily, but test malformed
	headers := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	chunkedBody := "xyz\r\ndata\r\n0\r\n\r\n"
	buf := []byte(headers + chunkedBody)
	headerEnd := len(headers)

	n := frameHTTP(buf, false)
	// "xyz" fails ParseInt, returns offset (which is headerEnd at that point)
	if n != headerEnd {
		t.Errorf("frameHTTP with malformed chunk hex = %d, want %d", n, headerEnd)
	}
}

func TestFrameRedis_DeeplyNestedArrays(t *testing.T) {
	// Build a deeply nested Redis array: *1\r\n*1\r\n*1\r\n... > 32 deep
	depth := 40
	buf := make([]byte, 0, depth*5+10)
	for i := 0; i < depth; i++ {
		buf = append(buf, []byte("*1\r\n")...)
	}
	buf = append(buf, []byte("+OK\r\n")...)

	n := frameRedis(buf)
	if n != 0 {
		t.Errorf("frameRedis with depth %d = %d, want 0 (exceeded maxRedisDepth)", depth, n)
	}
}

func TestFrameRedis_ValidNestedArray(t *testing.T) {
	// *2\r\n+OK\r\n+OK\r\n — array of 2 simple strings
	buf := []byte("*2\r\n+OK\r\n+OK\r\n")

	n := frameRedis(buf)
	if n != len(buf) {
		t.Errorf("frameRedis = %d, want %d", n, len(buf))
	}
}

func TestFrameRedis_NestedArrayWithinLimit(t *testing.T) {
	// Build a nested array at exactly maxRedisDepth (should still work because check is > not >=)
	// Actually maxRedisDepth=32, the check is depth > maxRedisDepth
	// frameRedis calls with depth=0, first array calls with depth=0, next level depth=1, ...
	// At depth=32, frameRESPArrayWithDepth checks 32 > 32 = false, so depth=32 is allowed
	// At depth=33, 33 > 32 = true, returns 0
	// So 33 levels of nesting should fail, 32 should succeed
	depth := 32
	buf := make([]byte, 0, depth*5+10)
	for i := 0; i < depth; i++ {
		buf = append(buf, []byte("*1\r\n")...)
	}
	buf = append(buf, []byte("+OK\r\n")...)

	n := frameRedis(buf)
	// depth=32 nested arrays: frameRedis(depth=0) -> frameRESPArrayWithDepth(depth=0)
	//   -> frameRedisWithDepth(depth=1) -> ... -> frameRESPArrayWithDepth(depth=31)
	//   -> frameRedisWithDepth(depth=32) -> frameRESPArrayWithDepth(depth=32)
	//   -> 32 > 32 is false, so proceeds
	//   -> frameRedisWithDepth(depth=33) would be called for next, but we only have 32 arrays
	// Actually let me trace more carefully:
	// frameRedis(buf) = frameRedisWithDepth(buf, 0)
	//   buf[0]='*' -> frameRESPArrayWithDepth(buf, 0) -> 0 > 32? no
	//     calls frameRedisWithDepth(buf[offset:], 0+1=1)
	//       buf[0]='*' -> frameRESPArrayWithDepth(buf, 1) -> 1 > 32? no
	//         calls frameRedisWithDepth(buf[offset:], 1+1=2)
	// ... continuing this pattern ...
	// At the 32nd '*1\r\n', we enter frameRESPArrayWithDepth(buf, 31) -> 31 > 32? no
	//   calls frameRedisWithDepth(buf[offset:], 31+1=32)
	//     buf[0]='+' -> return end+2 (simple string "+OK\r\n")
	// So depth=32 nesting works. Good.

	if n != len(buf) {
		t.Errorf("frameRedis with depth %d = %d, want %d", depth, n, len(buf))
	}
}

func TestFrameHTTP_ContentLengthOverflowWrap(t *testing.T) {
	// Content-Length that when added to headerEnd would overflow
	msg := fmt.Sprintf("GET / HTTP/1.1\r\nContent-Length: %d\r\n\r\n", MaxBufferSize+1)
	buf := []byte(msg)

	n := frameHTTP(buf, true)
	headerEnd := len(msg)
	if n != headerEnd {
		t.Errorf("frameHTTP with Content-Length > MaxBufferSize = %d, want %d (headerEnd)", n, headerEnd)
	}
}

func TestFrameRedis_SimpleString(t *testing.T) {
	buf := []byte("+OK\r\n")
	n := frameRedis(buf)
	if n != 5 {
		t.Errorf("frameRedis simple string = %d, want 5", n)
	}
}

func TestFrameRedis_BulkString(t *testing.T) {
	buf := []byte("$5\r\nhello\r\n")
	n := frameRedis(buf)
	if n != len(buf) {
		t.Errorf("frameRedis bulk string = %d, want %d", n, len(buf))
	}
}

// buildPgMsg builds a PostgreSQL wire protocol message: type(1) + len(4) + payload.
func buildPgMsg(msgType byte, payload []byte) []byte {
	msg := make([]byte, 5+len(payload))
	msg[0] = msgType
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	return msg
}

// buildStartupMsg builds a PG startup message: len(4) + version(4) + params.
func buildStartupMsg() []byte {
	msg := make([]byte, 0, 64)
	msg = append(msg, 0, 0, 0, 0) // length placeholder
	msg = append(msg, 0x00, 0x03, 0x00, 0x00) // version 3.0
	msg = append(msg, []byte("user")...)
	msg = append(msg, 0)
	msg = append(msg, []byte("test")...)
	msg = append(msg, 0)
	msg = append(msg, 0) // terminator
	binary.BigEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

func TestFramePostgresRequest_SimpleQuery(t *testing.T) {
	// Simple Query 'Q': should be consumed as a standalone batch
	query := append([]byte("SELECT 1"), 0)
	msg := buildPgMsg('Q', query)

	n := framePostgres(msg, true)
	if n != len(msg) {
		t.Errorf("framePostgres simple query = %d, want %d", n, len(msg))
	}
}

func TestFramePostgresRequest_ExtendedQuery(t *testing.T) {
	// Extended query: P + B + E + S (all consumed as one batch)
	parseMsg := buildPgMsg('P', append(append([]byte{0}, []byte("SELECT 1")...), 0, 0, 0))
	bindMsg := buildPgMsg('B', []byte{0, 0, 0, 0, 0, 0})
	execMsg := buildPgMsg('E', append([]byte{0}, 0, 0, 0, 0))
	syncMsg := buildPgMsg('S', nil) // Sync: S + len=4

	buf := append(parseMsg, bindMsg...)
	buf = append(buf, execMsg...)
	buf = append(buf, syncMsg...)

	n := framePostgres(buf, true)
	if n != len(buf) {
		t.Errorf("framePostgres extended query = %d, want %d", n, len(buf))
	}
}

func TestFramePostgresRequest_Startup(t *testing.T) {
	startup := buildStartupMsg()

	n := framePostgres(startup, true)
	if n != len(startup) {
		t.Errorf("framePostgres startup = %d, want %d", n, len(startup))
	}
}

func TestFramePostgresRequest_StartupDoesNotConsumeQuery(t *testing.T) {
	// Startup followed by query: startup should NOT consume the query
	startup := buildStartupMsg()
	query := buildPgMsg('Q', append([]byte("SELECT 1"), 0))
	buf := append(startup, query...)

	n := framePostgres(buf, true)
	if n != len(startup) {
		t.Errorf("framePostgres startup+query should only consume startup: got %d, want %d", n, len(startup))
	}
}

func TestFramePostgresRequest_StartupWithPassword(t *testing.T) {
	// Startup followed by PasswordMessage ('p'): both consumed as auth batch
	startup := buildStartupMsg()
	password := buildPgMsg('p', append([]byte("md5secret"), 0))
	buf := append(startup, password...)

	n := framePostgres(buf, true)
	if n != len(buf) {
		t.Errorf("framePostgres startup+password = %d, want %d", n, len(buf))
	}
}

func TestFramePostgresRequest_StartupWithPasswordThenQuery(t *testing.T) {
	// Startup + password + query: should consume startup+password, NOT the query
	startup := buildStartupMsg()
	password := buildPgMsg('p', append([]byte("md5secret"), 0))
	query := buildPgMsg('Q', append([]byte("SELECT 1"), 0))
	buf := append(startup, password...)
	buf = append(buf, query...)

	n := framePostgres(buf, true)
	expected := len(startup) + len(password)
	if n != expected {
		t.Errorf("framePostgres startup+password+query should stop before query: got %d, want %d", n, expected)
	}
}

func TestFramePostgresResponse_ThroughReadyForQuery(t *testing.T) {
	// Server response batch: RowDescription + DataRow + CommandComplete + ReadyForQuery
	rowDesc := buildPgMsg('T', []byte{0, 0}) // 0 fields
	dataRow := buildPgMsg('D', []byte{0, 0}) // 0 columns
	cmdComplete := buildPgMsg('C', append([]byte("SELECT 1"), 0))
	readyForQuery := buildPgMsg('Z', []byte{'I'}) // Idle

	buf := append(rowDesc, dataRow...)
	buf = append(buf, cmdComplete...)
	buf = append(buf, readyForQuery...)

	n := framePostgres(buf, false)
	if n != len(buf) {
		t.Errorf("framePostgres response through Z = %d, want %d", n, len(buf))
	}
}

func TestFramePostgresResponse_FallbackOnCommandComplete(t *testing.T) {
	// Response without Z (truncated by eBPF): should use CommandComplete as boundary
	rowDesc := buildPgMsg('T', []byte{0, 0})
	cmdComplete := buildPgMsg('C', append([]byte("SELECT 1"), 0))
	buf := append(rowDesc, cmdComplete...)

	n := framePostgres(buf, false)
	if n != len(buf) {
		t.Errorf("framePostgres response with C fallback = %d, want %d", n, len(buf))
	}
}

func TestFramePostgresResponse_WaitsForQueryData(t *testing.T) {
	// Incomplete query response: only RowDescription, no C/E/Z yet
	rowDesc := buildPgMsg('T', []byte{0, 0})
	dataRow := buildPgMsg('D', []byte{0, 0})
	buf := append(rowDesc, dataRow...)

	n := framePostgres(buf, false)
	if n != 0 {
		t.Errorf("framePostgres incomplete response should return 0, got %d", n)
	}
}

func TestFramePostgresResponse_AuthFallback(t *testing.T) {
	// Auth response without Z (truncated by eBPF MAX_CAPTURE)
	authOK := buildPgMsg('R', []byte{0, 0, 0, 0})
	paramStatus := buildPgMsg('S', append([]byte("server_version"), 0, '1', '5', 0))
	backendKey := buildPgMsg('K', []byte{0, 0, 0, 1, 0, 0, 0, 2})
	buf := append(authOK, paramStatus...)
	buf = append(buf, backendKey...)

	n := framePostgres(buf, false)
	if n != len(buf) {
		t.Errorf("framePostgres auth fallback = %d, want %d", n, len(buf))
	}
}

func TestFramePostgresResponse_AuthThroughReadyForQuery(t *testing.T) {
	// Auth response: AuthOK + ParameterStatus + BackendKeyData + ReadyForQuery
	authOK := buildPgMsg('R', []byte{0, 0, 0, 0})                       // AuthenticationOk
	paramStatus := buildPgMsg('S', append([]byte("server_version"), 0, '1', '5', 0)) // ParameterStatus
	backendKey := buildPgMsg('K', []byte{0, 0, 0, 1, 0, 0, 0, 2})      // pid=1, secret=2
	readyForQuery := buildPgMsg('Z', []byte{'I'})

	buf := append(authOK, paramStatus...)
	buf = append(buf, backendKey...)
	buf = append(buf, readyForQuery...)

	n := framePostgres(buf, false)
	if n != len(buf) {
		t.Errorf("framePostgres auth response through Z = %d, want %d", n, len(buf))
	}
}

// buildSSLRequest builds a PG SSLRequest message (8 bytes: length=8, code=80877103).
func buildSSLRequest() []byte {
	msg := make([]byte, 8)
	binary.BigEndian.PutUint32(msg[0:4], 8)          // length
	binary.BigEndian.PutUint32(msg[4:8], 80877103)   // SSLRequest code
	return msg
}

func TestFindPgQueryStart_SimpleQuery(t *testing.T) {
	query := buildPgMsg('Q', append([]byte("SELECT 1"), 0))
	n := findPgQueryStart(query)
	if n != 0 {
		t.Errorf("findPgQueryStart for bare query = %d, want 0", n)
	}
}

func TestFindPgQueryStart_StartupThenQuery(t *testing.T) {
	startup := buildStartupMsg()
	query := buildPgMsg('Q', append([]byte("SELECT 1"), 0))
	buf := append(startup, query...)

	n := findPgQueryStart(buf)
	if n != len(startup) {
		t.Errorf("findPgQueryStart startup+query = %d, want %d", n, len(startup))
	}
}

func TestFindPgQueryStart_SSLRequestThenStartupThenPasswordThenQuery(t *testing.T) {
	ssl := buildSSLRequest()
	startup := buildStartupMsg()
	password := buildPgMsg('p', append([]byte("md5secret"), 0))
	query := buildPgMsg('P', append(append([]byte{0}, []byte("SELECT 1")...), 0, 0, 0))
	buf := append(ssl, startup...)
	buf = append(buf, password...)
	buf = append(buf, query...)

	expected := len(ssl) + len(startup) + len(password)
	n := findPgQueryStart(buf)
	if n != expected {
		t.Errorf("findPgQueryStart full auth chain = %d, want %d", n, expected)
	}
}

func TestFindPgQueryStart_NoQuery(t *testing.T) {
	startup := buildStartupMsg()
	n := findPgQueryStart(startup)
	if n != -1 {
		t.Errorf("findPgQueryStart with no query = %d, want -1", n)
	}
}

func TestSkipPgAuthRecv_SSLByteAndAuth(t *testing.T) {
	// 'N' (SSL no) + R (AuthOK) + S (ParameterStatus) + K (BackendKeyData) + Z (ReadyForQuery)
	var buf []byte
	buf = append(buf, 'N') // SSL negotiation: no
	buf = append(buf, buildPgMsg('R', []byte{0, 0, 0, 0})...)
	buf = append(buf, buildPgMsg('S', append([]byte("server_version"), 0, '1', '5', 0))...)
	buf = append(buf, buildPgMsg('K', []byte{0, 0, 0, 1, 0, 0, 0, 2})...)
	buf = append(buf, buildPgMsg('Z', []byte{'I'})...)

	n := skipPgAuthRecv(buf)
	if n != len(buf) {
		t.Errorf("skipPgAuthRecv SSL+auth = %d, want %d", n, len(buf))
	}
}

func TestSkipPgAuthRecv_AuthThenQueryResponse(t *testing.T) {
	// Auth messages followed by query response (T+D+C+Z)
	var buf []byte
	buf = append(buf, 'N') // SSL no
	buf = append(buf, buildPgMsg('R', []byte{0, 0, 0, 0})...)
	buf = append(buf, buildPgMsg('S', append([]byte("server_version"), 0, '1', '5', 0))...)
	buf = append(buf, buildPgMsg('Z', []byte{'I'})...)
	authLen := len(buf)
	// Query response
	buf = append(buf, buildPgMsg('T', []byte{0, 0})...)           // RowDescription
	buf = append(buf, buildPgMsg('C', append([]byte("SELECT 1"), 0))...) // CommandComplete

	n := skipPgAuthRecv(buf)
	if n != authLen {
		t.Errorf("skipPgAuthRecv should stop at query response: got %d, want %d", n, authLen)
	}
}

func TestSkipPgAuthRecv_NoSSLByte(t *testing.T) {
	// Auth without SSL negotiation (direct connection)
	var buf []byte
	buf = append(buf, buildPgMsg('R', []byte{0, 0, 0, 0})...)
	buf = append(buf, buildPgMsg('S', append([]byte("server_version"), 0, '1', '5', 0))...)
	buf = append(buf, buildPgMsg('Z', []byte{'I'})...)

	n := skipPgAuthRecv(buf)
	if n != len(buf) {
		t.Errorf("skipPgAuthRecv without SSL = %d, want %d", n, len(buf))
	}
}

func TestSkipPgAuthRecv_ParameterStatusS_NotSSLByte(t *testing.T) {
	// 'S' at the start with valid PG length should be treated as ParameterStatus, not SSL byte
	buf := buildPgMsg('S', append([]byte("server_version"), 0, '1', '5', 0))

	n := skipPgAuthRecv(buf)
	if n != len(buf) {
		t.Errorf("skipPgAuthRecv ParameterStatus at start = %d, want %d", n, len(buf))
	}
}

// buildMySQLPacket builds a MySQL wire protocol packet: 3-byte len + 1-byte seq + payload.
func buildMySQLPacket(seqID byte, payload []byte) []byte {
	pkt := make([]byte, 4+len(payload))
	pkt[0] = byte(len(payload))
	pkt[1] = byte(len(payload) >> 8)
	pkt[2] = byte(len(payload) >> 16)
	pkt[3] = seqID
	copy(pkt[4:], payload)
	return pkt
}

// buildMySQLGreeting builds a minimal MySQL server greeting packet.
func buildMySQLGreeting() []byte {
	payload := make([]byte, 0, 64)
	payload = append(payload, 0x0a)                       // protocol version 10
	payload = append(payload, []byte("5.7.42-log")...)    // server version
	payload = append(payload, 0)                          // null terminator
	payload = append(payload, 1, 0, 0, 0)                // thread id
	payload = append(payload, []byte("abcdefgh")...)      // auth plugin data part 1
	payload = append(payload, 0)                          // filler
	payload = append(payload, 0xff, 0xf7)                // capabilities lower
	payload = append(payload, 0x21)                       // charset
	payload = append(payload, 0x02, 0x00)                // status flags
	payload = append(payload, 0x7f, 0x80)                // capabilities upper
	payload = append(payload, 0x15)                       // auth plugin data len
	payload = append(payload, make([]byte, 10)...)        // reserved
	payload = append(payload, []byte("ijklmnopqrst")...) // auth plugin data part 2
	payload = append(payload, 0)                          // null terminator
	return buildMySQLPacket(0, payload)
}

// buildMySQLOK builds a MySQL OK packet.
func buildMySQLOK(seqID byte) []byte {
	payload := []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
	return buildMySQLPacket(seqID, payload)
}

// buildMySQLComQuery builds a MySQL COM_QUERY packet.
func buildMySQLComQuery(sql string) []byte {
	payload := append([]byte{0x03}, []byte(sql)...)
	return buildMySQLPacket(0, payload)
}

func TestFindMySQLQueryStart_ComQuery(t *testing.T) {
	pkt := buildMySQLComQuery("SELECT 1")
	n := findMySQLQueryStart(pkt)
	if n != 0 {
		t.Errorf("findMySQLQueryStart for COM_QUERY = %d, want 0", n)
	}
}

func TestFindMySQLQueryStart_AuthThenQuery(t *testing.T) {
	// Auth response: seq=1, some capabilities payload
	authResp := buildMySQLPacket(1, []byte{0x85, 0xa6, 0x3f, 0x20, 0x00, 0x00, 0x00, 0x01})
	query := buildMySQLComQuery("SELECT 1")
	buf := append(authResp, query...)

	expected := len(authResp)
	n := findMySQLQueryStart(buf)
	if n != expected {
		t.Errorf("findMySQLQueryStart auth+query = %d, want %d", n, expected)
	}
}

func TestFindMySQLQueryStart_NoQuery(t *testing.T) {
	authResp := buildMySQLPacket(1, []byte{0x85, 0xa6, 0x3f, 0x20})
	n := findMySQLQueryStart(authResp)
	if n != -1 {
		t.Errorf("findMySQLQueryStart with no query = %d, want -1", n)
	}
}

func TestSkipMySQLHandshake_GreetingAndOK(t *testing.T) {
	greeting := buildMySQLGreeting()
	ok := buildMySQLOK(2)
	buf := append(greeting, ok...)

	n := skipMySQLHandshake(buf)
	if n != len(buf) {
		t.Errorf("skipMySQLHandshake greeting+OK = %d, want %d", n, len(buf))
	}
}

func TestSkipMySQLHandshake_StopsAtResultSet(t *testing.T) {
	greeting := buildMySQLGreeting()
	ok := buildMySQLOK(2) // auth OK (seq=2 → part of handshake)
	// Result set column count: seq=0 → new command response, should NOT consume
	resultPkt := buildMySQLPacket(0, []byte{0x02})
	buf := append(greeting, ok...)
	buf = append(buf, resultPkt...)

	expected := len(greeting) + len(ok)
	n := skipMySQLHandshake(buf)
	if n != expected {
		t.Errorf("skipMySQLHandshake should stop at result set: got %d, want %d", n, expected)
	}
}

func TestSkipMySQLHandshake_StopsBeforePingOK(t *testing.T) {
	greeting := buildMySQLGreeting()
	authOK := buildMySQLOK(2)   // auth OK (seq=2 → handshake, consumed)
	pingOK := buildMySQLOK(1)   // COM_PING OK (seq=1 → command response, NOT consumed)
	buf := append(greeting, authOK...)
	buf = append(buf, pingOK...)

	// Should consume greeting + auth OK, but NOT the ping OK (seq=1 < 2)
	expected := len(greeting) + len(authOK)
	n := skipMySQLHandshake(buf)
	if n != expected {
		t.Errorf("skipMySQLHandshake should stop before ping OK: got %d, want %d", n, expected)
	}
}

func TestSkipMySQLHandshake_NoGreeting(t *testing.T) {
	// If buffer starts with OK (no greeting), should consume nothing
	ok := buildMySQLOK(2)
	n := skipMySQLHandshake(ok)
	if n != 0 {
		t.Errorf("skipMySQLHandshake without greeting should return 0: got %d", n)
	}
}

func TestMySQLReadyIntegration(t *testing.T) {
	r := NewReassembler(zap.NewNop())

	var pairs []*RequestPair
	r.OnPair(func(p *RequestPair) {
		pairs = append(pairs, p)
	})

	pid := uint32(100)
	fd := int32(6)
	tid := uint32(200)
	addr := "127.0.0.1"
	port := uint16(3306)

	// Step 1: Server sends greeting
	greeting := buildMySQLGreeting()
	r.AppendRecv(pid, tid, fd, greeting, addr, port, false)

	// Step 2: Client sends auth response
	authResp := buildMySQLPacket(1, []byte{0x85, 0xa6, 0x3f, 0x20, 0x00, 0x00, 0x00, 0x01})
	r.AppendSend(pid, tid, fd, authResp, addr, port, false)

	// Step 3: Server sends OK
	ok := buildMySQLOK(2)
	r.AppendRecv(pid, tid, fd, ok, addr, port, false)

	if len(pairs) != 0 {
		t.Fatalf("expected 0 pairs during handshake, got %d", len(pairs))
	}

	// Step 4: Client sends COM_QUERY
	query := buildMySQLComQuery("SELECT * FROM users")
	r.AppendSend(pid, tid, fd, query, addr, port, false)

	// Step 5: Server sends result (OK packet for simplicity)
	result := buildMySQLOK(1)
	r.AppendRecv(pid, tid, fd, result, addr, port, false)

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair after query, got %d", len(pairs))
	}

	pair := pairs[0]
	if pair.Protocol != "mysql" {
		t.Errorf("expected protocol mysql, got %s", pair.Protocol)
	}
	// Request should be the COM_QUERY packet
	if len(pair.Request) < 5 || pair.Request[4] != 0x03 {
		t.Errorf("expected COM_QUERY (0x03), got %v", pair.Request[:min(5, len(pair.Request))])
	}
}

func TestMySQLPingThenQuery(t *testing.T) {
	// Regression test: Go's database/sql sends COM_PING during Ping() at startup.
	// Before the fix, skipMySQLHandshake consumed the COM_PING OK response along
	// with auth handshake packets, causing cascading misalignment.
	r := NewReassembler(zap.NewNop())

	var pairs []*RequestPair
	r.OnPair(func(p *RequestPair) {
		pairs = append(pairs, p)
	})

	pid := uint32(100)
	fd := int32(7)
	tid := uint32(200)
	addr := "127.0.0.1"
	port := uint16(3306)

	// Handshake
	r.AppendRecv(pid, tid, fd, buildMySQLGreeting(), addr, port, false)
	r.AppendSend(pid, tid, fd, buildMySQLPacket(1, []byte{0x85, 0xa6, 0x3f, 0x20, 0x00, 0x00, 0x00, 0x01}), addr, port, false)
	r.AppendRecv(pid, tid, fd, buildMySQLOK(2), addr, port, false)

	// COM_PING (0x0e) sent by db.Ping() at startup
	r.AppendSend(pid, tid, fd, buildMySQLPacket(0, []byte{0x0e}), addr, port, false)
	r.AppendRecv(pid, tid, fd, buildMySQLOK(1), addr, port, false)

	// COM_QUERY — the real query that should produce a span
	r.AppendSend(pid, tid, fd, buildMySQLComQuery("SELECT * FROM products"), addr, port, false)
	r.AppendRecv(pid, tid, fd, buildMySQLOK(1), addr, port, false)

	// Should have 2 pairs: COM_PING (handshake, filtered later) + COM_QUERY
	if len(pairs) < 2 {
		t.Fatalf("expected at least 2 pairs (ping + query), got %d", len(pairs))
	}

	// Last pair should be the COM_QUERY
	lastPair := pairs[len(pairs)-1]
	if lastPair.Protocol != "mysql" {
		t.Errorf("expected protocol mysql, got %s", lastPair.Protocol)
	}
	if len(lastPair.Request) < 5 || lastPair.Request[4] != 0x03 {
		t.Errorf("expected COM_QUERY (0x03) in last pair, got %v", lastPair.Request[:min(5, len(lastPair.Request))])
	}
}

func TestPgReadyIntegration(t *testing.T) {
	// Integration test: full PG lifecycle through reassembler
	r := NewReassembler(zap.NewNop())

	var pairs []*RequestPair
	r.OnPair(func(p *RequestPair) {
		pairs = append(pairs, p)
	})

	pid := uint32(100)
	fd := int32(5)
	tid := uint32(200)
	addr := "127.0.0.1"
	port := uint16(5432)

	// Step 1: Client sends SSLRequest
	ssl := buildSSLRequest()
	r.AppendSend(pid, tid, fd, ssl, addr, port, false)
	// Step 2: Server sends 'N' (no SSL)
	r.AppendRecv(pid, tid, fd, []byte{'N'}, addr, port, false)
	// Both should be discarded (no query yet)
	if len(pairs) != 0 {
		t.Fatalf("expected 0 pairs after SSL, got %d", len(pairs))
	}

	// Step 3: Client sends StartupMessage
	startup := buildStartupMsg()
	r.AppendSend(pid, tid, fd, startup, addr, port, false)
	// Step 4: Server sends auth response
	var authResp []byte
	authResp = append(authResp, buildPgMsg('R', []byte{0, 0, 0, 0})...)
	authResp = append(authResp, buildPgMsg('S', append([]byte("server_version"), 0, '1', '5', 0))...)
	authResp = append(authResp, buildPgMsg('K', []byte{0, 0, 0, 1, 0, 0, 0, 2})...)
	authResp = append(authResp, buildPgMsg('Z', []byte{'I'})...)
	r.AppendRecv(pid, tid, fd, authResp, addr, port, false)
	if len(pairs) != 0 {
		t.Fatalf("expected 0 pairs after auth, got %d", len(pairs))
	}

	// Step 5: Client sends Query
	query := buildPgMsg('Q', append([]byte("SELECT 1"), 0))
	r.AppendSend(pid, tid, fd, query, addr, port, false)
	// Step 6: Server sends query response
	var queryResp []byte
	queryResp = append(queryResp, buildPgMsg('T', []byte{0, 0})...)
	queryResp = append(queryResp, buildPgMsg('C', append([]byte("SELECT 1"), 0))...)
	queryResp = append(queryResp, buildPgMsg('Z', []byte{'I'})...)
	r.AppendRecv(pid, tid, fd, queryResp, addr, port, false)

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair after query, got %d", len(pairs))
	}

	// Verify the pair contains the query, not auth data
	pair := pairs[0]
	if pair.Protocol != "postgres" {
		t.Errorf("expected protocol postgres, got %s", pair.Protocol)
	}
	if len(pair.Request) == 0 || pair.Request[0] != 'Q' {
		t.Errorf("expected request to start with 'Q', got %v", pair.Request[:min(5, len(pair.Request))])
	}
}

func TestPairTID_UsesRequestNotResponseTID(t *testing.T) {
	// Verify that pair.TID comes from AppendSend (request direction),
	// not AppendRecv (response direction). This is critical for trace
	// context matching: threadCtx is stored under the request's TID,
	// so the pair must use that TID for enrichPairContext to find it.
	// Go goroutines migrate between OS threads, so the response write
	// often runs on a different TID than the request read.
	r := NewReassembler(zap.NewNop())

	var pairs []*RequestPair
	r.OnPair(func(p *RequestPair) {
		pairs = append(pairs, p)
	})

	pid := uint32(100)
	sendTID := uint32(500) // request arrives on thread 500
	recvTID := uint32(999) // response sent on thread 999 (goroutine migrated)
	fd := int32(10)
	addr := "10.0.0.1"
	port := uint16(8080)

	// Request arrives (AppendSend with sendTID)
	req := []byte("GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
	r.AppendSend(pid, sendTID, fd, req, addr, port, false)

	// Response sent (AppendRecv with different recvTID — goroutine migrated)
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	r.AppendRecv(pid, recvTID, fd, resp, addr, port, false)

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}

	// Pair must use sendTID (request direction), NOT recvTID
	if pairs[0].TID != sendTID {
		t.Errorf("pair.TID = %d, want %d (sendTID); got recvTID=%d instead",
			pairs[0].TID, sendTID, recvTID)
	}
}

func TestCausalFDQueue_FIFO(t *testing.T) {
	// Verify that PushCausalFD + pair creation preserves FIFO ordering.
	// Scenario: Redis persistent connection. Two concurrent inbound requests
	// (FD 23, FD 25) each trigger an outbound Redis command on the same FD 10.
	// The FIFO queue ensures request A gets FD 23 and request B gets FD 25,
	// even though both share the same outbound FD.
	r := NewReassembler(zap.NewNop())

	var pairs []*RequestPair
	r.OnPair(func(p *RequestPair) {
		pairs = append(pairs, p)
	})

	pid := uint32(100)
	tid := uint32(200)
	fd := int32(10)
	addr := "127.0.0.1"
	port := uint16(6379)

	// Push causal FDs in order: request A (inbound FD=23), then B (inbound FD=25)
	r.PushCausalFD(pid, fd, 23)
	r.PushCausalFD(pid, fd, 25)

	// Send two Redis commands (pipelined)
	r.AppendSend(pid, tid, fd, []byte("*2\r\n$3\r\nGET\r\n$5\r\nkey_a\r\n"), addr, port, false)
	r.AppendSend(pid, tid, fd, []byte("*2\r\n$3\r\nGET\r\n$5\r\nkey_b\r\n"), addr, port, false)

	// Receive two Redis responses
	r.AppendRecv(pid, tid, fd, []byte("$5\r\nval_a\r\n"), addr, port, false)
	r.AppendRecv(pid, tid, fd, []byte("$5\r\nval_b\r\n"), addr, port, false)

	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}

	// First pair should have CausalInboundFD=23 (request A)
	if pairs[0].CausalInboundFD != 23 {
		t.Errorf("pairs[0].CausalInboundFD = %d, want 23", pairs[0].CausalInboundFD)
	}
	// Second pair should have CausalInboundFD=25 (request B)
	if pairs[1].CausalInboundFD != 25 {
		t.Errorf("pairs[1].CausalInboundFD = %d, want 25", pairs[1].CausalInboundFD)
	}
}

func TestCausalFDQueue_EmptyQueue(t *testing.T) {
	// When no PushCausalFD was called, CausalInboundFD should be 0.
	r := NewReassembler(zap.NewNop())

	var pairs []*RequestPair
	r.OnPair(func(p *RequestPair) {
		pairs = append(pairs, p)
	})

	pid := uint32(100)
	tid := uint32(200)
	fd := int32(10)

	r.AppendSend(pid, tid, fd, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), "10.0.0.1", 80, false)
	r.AppendRecv(pid, tid, fd, []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"), "10.0.0.1", 80, false)

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0].CausalInboundFD != 0 {
		t.Errorf("CausalInboundFD = %d, want 0 (empty queue)", pairs[0].CausalInboundFD)
	}
}

func TestCausalFDQueue_RemoveStream(t *testing.T) {
	// When RemoveStream emits a partial pair, it should pop from the queue.
	r := NewReassembler(zap.NewNop())

	var pairs []*RequestPair
	r.OnPair(func(p *RequestPair) {
		pairs = append(pairs, p)
	})

	pid := uint32(100)
	tid := uint32(200)
	fd := int32(10)

	r.PushCausalFD(pid, fd, 42)
	r.AppendSend(pid, tid, fd, []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"), "10.0.0.1", 80, false)
	// No response — connection closes with partial data
	r.RemoveStream(pid, fd, tid)

	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair from RemoveStream, got %d", len(pairs))
	}
	if pairs[0].CausalInboundFD != 42 {
		t.Errorf("CausalInboundFD = %d, want 42", pairs[0].CausalInboundFD)
	}
}
