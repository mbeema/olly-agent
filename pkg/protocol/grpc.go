package protocol

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// HTTP/2 constants
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

const (
	http2FrameData         = 0x0
	http2FrameHeaders      = 0x1
	http2FramePriority     = 0x2
	http2FrameRSTStream    = 0x3
	http2FrameSettings     = 0x4
	http2FramePushPromise  = 0x5
	http2FramePing         = 0x6
	http2FrameGoAway       = 0x7
	http2FrameWindowUpdate = 0x8
	http2FrameContinuation = 0x9

	// HEADERS frame flags
	http2FlagHeadersEndStream  = 0x1
	http2FlagHeadersEndHeaders = 0x4
	http2FlagHeadersPadded     = 0x8
	http2FlagHeadersPriority   = 0x20
)

// GRPCParser parses gRPC over HTTP/2.
type GRPCParser struct{}

func (p *GRPCParser) Name() string { return ProtoGRPC }

func (p *GRPCParser) Detect(data []byte, port uint16) bool {
	if len(data) < 9 {
		return false
	}

	// HTTP/2 connection preface
	if bytes.HasPrefix(data, http2Preface) {
		return true
	}

	// HTTP/2 frame: 3-byte length + 1-byte type + 1-byte flags + 4-byte stream ID
	frameLen := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
	frameType := data[3]

	// Valid frame types and reasonable length
	if frameLen < 16384 && frameType <= 0x09 {
		if frameType == http2FrameHeaders || frameType == http2FrameSettings {
			return true
		}
	}

	// Check for gRPC content-type in raw data (literal headers)
	if len(data) > 512 {
		if bytes.Contains(data[:512], []byte("application/grpc")) {
			return true
		}
	} else if bytes.Contains(data, []byte("application/grpc")) {
		return true
	}

	// Port fallback
	return port == 50051
}

func (p *GRPCParser) Parse(request, response []byte) (*SpanAttributes, error) {
	attrs := &SpanAttributes{
		Protocol: ProtoGRPC,
	}

	// Decode HTTP/2 headers from request using HPACK
	reqHeaders := p.decodeHTTP2Headers(request)
	respHeaders := p.decodeHTTP2Headers(response)

	// Extract :path from request headers
	path := headerValue(reqHeaders, ":path")
	if path == "" {
		// Fallback: search raw data for path patterns
		path = findPathInRaw(request)
	}

	if path != "" {
		// gRPC path format: /package.ServiceName/MethodName
		parts := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)
		if len(parts) == 2 {
			attrs.GRPCService = parts[0]
			attrs.GRPCMethod = parts[1]
		}
	}

	// Extract content-type to confirm gRPC
	ct := headerValue(reqHeaders, "content-type")
	if ct == "" {
		ct = headerValue(reqHeaders, "Content-Type")
	}
	if strings.HasPrefix(ct, "application/grpc") {
		// confirmed gRPC
	}

	// Extract gRPC status from response headers/trailers
	grpcStatus := headerValue(respHeaders, "grpc-status")
	if grpcStatus != "" {
		attrs.GRPCStatus = parseGRPCStatus(grpcStatus)
	} else {
		// Try raw extraction as fallback
		attrs.GRPCStatus = p.extractStatusRaw(response)
	}

	if attrs.GRPCStatus != 0 {
		attrs.Error = true
		attrs.ErrorMsg = fmt.Sprintf("gRPC status %d", attrs.GRPCStatus)
		grpcMsg := headerValue(respHeaders, "grpc-message")
		if grpcMsg != "" {
			attrs.ErrorMsg = fmt.Sprintf("gRPC status %d: %s", attrs.GRPCStatus, grpcMsg)
		}
	}

	// Extract HTTP/2 :status
	httpStatus := headerValue(respHeaders, ":status")
	if httpStatus != "" {
		attrs.HTTPStatusCode = parseHTTPStatus(httpStatus)
	}

	// Extract :method
	method := headerValue(reqHeaders, ":method")
	if method != "" {
		attrs.HTTPMethod = method
	} else {
		attrs.HTTPMethod = "POST" // gRPC always uses POST
	}

	// Build span name
	if attrs.GRPCService != "" && attrs.GRPCMethod != "" {
		attrs.Name = fmt.Sprintf("%s/%s", attrs.GRPCService, attrs.GRPCMethod)
	} else if path != "" {
		attrs.Name = path
	} else {
		attrs.Name = "gRPC"
	}

	return attrs, nil
}

// decodeHTTP2Headers walks HTTP/2 frames and decodes HPACK-encoded headers.
func (p *GRPCParser) decodeHTTP2Headers(data []byte) []hpack.HeaderField {
	if len(data) == 0 {
		return nil
	}

	// Skip connection preface if present
	if bytes.HasPrefix(data, http2Preface) {
		data = data[len(http2Preface):]
	}

	var headerBlocks []byte
	decoder := hpack.NewDecoder(4096, nil)

	// Walk through HTTP/2 frames
	for len(data) >= 9 {
		frameLen := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		frameType := data[3]
		flags := data[4]
		// streamID: data[5:9] (masked with 0x7FFFFFFF)

		payloadStart := uint32(9)
		payloadEnd := payloadStart + frameLen

		if payloadEnd > uint32(len(data)) {
			break
		}

		payload := data[payloadStart:payloadEnd]

		if frameType == http2FrameHeaders {
			headerPayload := payload

			// Handle PADDED flag
			if flags&http2FlagHeadersPadded != 0 && len(headerPayload) > 0 {
				padLen := int(headerPayload[0])
				headerPayload = headerPayload[1:]
				if padLen < len(headerPayload) {
					headerPayload = headerPayload[:len(headerPayload)-padLen]
				}
			}

			// Handle PRIORITY flag
			if flags&http2FlagHeadersPriority != 0 && len(headerPayload) >= 5 {
				headerPayload = headerPayload[5:] // skip 4-byte dependency + 1-byte weight
			}

			headerBlocks = append(headerBlocks, headerPayload...)

			// If END_HEADERS is set, decode now
			if flags&http2FlagHeadersEndHeaders != 0 {
				headers, err := decoder.DecodeFull(headerBlocks)
				if err == nil {
					return headers
				}
				// Reset for next header block
				headerBlocks = nil
			}
		} else if frameType == http2FrameContinuation {
			// CONTINUATION frames carry more header block fragments
			headerBlocks = append(headerBlocks, payload...)

			if flags&http2FlagHeadersEndHeaders != 0 {
				headers, err := decoder.DecodeFull(headerBlocks)
				if err == nil {
					return headers
				}
				headerBlocks = nil
			}
		}

		data = data[payloadEnd:]
	}

	// If we have leftover header blocks (no END_HEADERS seen), try to decode anyway
	if len(headerBlocks) > 0 {
		headers, err := decoder.DecodeFull(headerBlocks)
		if err == nil {
			return headers
		}
	}

	return nil
}

// headerValue finds a header value by name (case-insensitive for non-pseudo headers).
func headerValue(headers []hpack.HeaderField, name string) string {
	for _, h := range headers {
		if h.Name == name {
			return h.Value
		}
		// HTTP/2 headers are lowercase, but handle mixed case for safety
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// parseGRPCStatus parses a gRPC status code string.
func parseGRPCStatus(s string) int {
	status := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			status = status*10 + int(c-'0')
		} else {
			break
		}
	}
	return status
}

// parseHTTPStatus parses an HTTP status code string.
func parseHTTPStatus(s string) int {
	status := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			status = status*10 + int(c-'0')
		} else {
			break
		}
	}
	return status
}

// extractStatusRaw is a fallback that searches raw bytes for grpc-status.
func (p *GRPCParser) extractStatusRaw(data []byte) int {
	marker := []byte("grpc-status")
	idx := bytes.Index(data, marker)
	if idx < 0 {
		return 0
	}

	offset := idx + len(marker)
	for offset < len(data) && (data[offset] == ':' || data[offset] == ' ') {
		offset++
	}

	if offset < len(data) && data[offset] >= '0' && data[offset] <= '9' {
		status := int(data[offset] - '0')
		offset++
		if offset < len(data) && data[offset] >= '0' && data[offset] <= '9' {
			status = status*10 + int(data[offset]-'0')
		}
		return status
	}

	return 0
}

// findPathInRaw looks for gRPC-style paths in raw data.
func findPathInRaw(data []byte) string {
	// Look for /service.Name/Method pattern
	for i := 0; i < len(data)-1; i++ {
		if data[i] == '/' && isAlphaNum(data[i+1]) {
			end := i + 1
			slashes := 0
			for end < len(data) && (isAlphaNum(data[end]) || data[end] == '/' || data[end] == '.') {
				if data[end] == '/' {
					slashes++
				}
				end++
			}
			path := string(data[i:end])
			// gRPC paths have exactly 2 slashes: /Service/Method
			if slashes == 1 && len(path) > 3 {
				return path
			}
		}
	}
	return ""
}

func isAlphaNum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_' || b == '-'
}

// ExtractGRPCMessageLength reads the gRPC length-prefixed message size.
func ExtractGRPCMessageLength(data []byte) (compressed bool, length uint32, ok bool) {
	if len(data) < 5 {
		return false, 0, false
	}
	compressed = data[0] == 1
	length = binary.BigEndian.Uint32(data[1:5])
	return compressed, length, true
}
