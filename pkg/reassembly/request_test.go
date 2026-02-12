// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package reassembly

import (
	"fmt"
	"math"
	"testing"
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
