// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// buildHTTP2HeadersFrame constructs a valid HTTP/2 HEADERS frame with HPACK-encoded headers.
func buildHTTP2HeadersFrame(streamID uint32, headers []hpack.HeaderField, endHeaders bool) []byte {
	var hpackBuf bytes.Buffer
	enc := hpack.NewEncoder(&hpackBuf)
	for _, h := range headers {
		enc.WriteField(h)
	}
	payload := hpackBuf.Bytes()

	frame := make([]byte, 9+len(payload))
	// 3-byte length
	frame[0] = byte(len(payload) >> 16)
	frame[1] = byte(len(payload) >> 8)
	frame[2] = byte(len(payload))
	// Type: HEADERS
	frame[3] = http2FrameHeaders
	// Flags
	flags := byte(0)
	if endHeaders {
		flags |= http2FlagHeadersEndHeaders
	}
	frame[4] = flags
	// Stream ID
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	copy(frame[9:], payload)

	return frame
}

func TestGRPCParseHPACK(t *testing.T) {
	p := &GRPCParser{}

	// Build a request with proper HPACK-encoded headers
	reqHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":path", Value: "/mypackage.UserService/GetUser"},
		{Name: ":authority", Value: "localhost:50051"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	}
	reqFrame := buildHTTP2HeadersFrame(1, reqHeaders, true)

	// Build a response with grpc-status in trailers
	respHeaders := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "grpc-status", Value: "0"},
	}
	respFrame := buildHTTP2HeadersFrame(1, respHeaders, true)

	attrs, err := p.Parse(reqFrame, respFrame)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if attrs.GRPCService != "mypackage.UserService" {
		t.Errorf("GRPCService = %q, want 'mypackage.UserService'", attrs.GRPCService)
	}
	if attrs.GRPCMethod != "GetUser" {
		t.Errorf("GRPCMethod = %q, want 'GetUser'", attrs.GRPCMethod)
	}
	if attrs.Name != "mypackage.UserService/GetUser" {
		t.Errorf("Name = %q, want 'mypackage.UserService/GetUser'", attrs.Name)
	}
	if attrs.HTTPMethod != "POST" {
		t.Errorf("HTTPMethod = %q, want 'POST'", attrs.HTTPMethod)
	}
	if attrs.GRPCStatus != 0 {
		t.Errorf("GRPCStatus = %d, want 0", attrs.GRPCStatus)
	}
	if attrs.HTTPStatusCode != 200 {
		t.Errorf("HTTPStatusCode = %d, want 200", attrs.HTTPStatusCode)
	}
}

func TestGRPCParseError(t *testing.T) {
	p := &GRPCParser{}

	reqHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/mypackage.UserService/GetUser"},
		{Name: "content-type", Value: "application/grpc"},
	}
	reqFrame := buildHTTP2HeadersFrame(1, reqHeaders, true)

	respHeaders := []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "grpc-status", Value: "5"},
		{Name: "grpc-message", Value: "User not found"},
	}
	respFrame := buildHTTP2HeadersFrame(1, respHeaders, true)

	attrs, err := p.Parse(reqFrame, respFrame)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if attrs.GRPCStatus != 5 {
		t.Errorf("GRPCStatus = %d, want 5 (NOT_FOUND)", attrs.GRPCStatus)
	}
	if !attrs.Error {
		t.Error("expected Error=true for non-zero gRPC status")
	}
	if attrs.ErrorMsg != "gRPC status 5: User not found" {
		t.Errorf("ErrorMsg = %q", attrs.ErrorMsg)
	}
}

func TestGRPCParsePrefaced(t *testing.T) {
	p := &GRPCParser{}

	// Include HTTP/2 connection preface before the HEADERS frame
	reqHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":path", Value: "/api.OrderService/CreateOrder"},
		{Name: "content-type", Value: "application/grpc+proto"},
	}
	headersFrame := buildHTTP2HeadersFrame(1, reqHeaders, true)
	reqFrame := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), headersFrame...)

	attrs, err := p.Parse(reqFrame, nil)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if attrs.GRPCService != "api.OrderService" {
		t.Errorf("GRPCService = %q, want 'api.OrderService'", attrs.GRPCService)
	}
	if attrs.GRPCMethod != "CreateOrder" {
		t.Errorf("GRPCMethod = %q, want 'CreateOrder'", attrs.GRPCMethod)
	}
}

func TestGRPCDetect(t *testing.T) {
	p := &GRPCParser{}

	// HTTP/2 preface
	if !p.Detect([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0) {
		t.Error("should detect HTTP/2 preface")
	}

	// SETTINGS frame (type=4)
	settings := make([]byte, 9)
	settings[3] = http2FrameSettings
	if !p.Detect(settings, 0) {
		t.Error("should detect SETTINGS frame")
	}

	// Port fallback
	if !p.Detect([]byte("some data"), 50051) {
		t.Error("should detect on port 50051")
	}

	// Random data on non-gRPC port
	if p.Detect([]byte("random data"), 8080) {
		t.Error("should not detect random data")
	}
}

func TestGRPCFallbackRawPath(t *testing.T) {
	p := &GRPCParser{}

	// Simulate data where HPACK decoding fails but raw path is present
	raw := []byte("garbage/service.Foo/BarMethod garbage")
	attrs, err := p.Parse(raw, nil)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if attrs.GRPCService != "service.Foo" {
		t.Errorf("GRPCService = %q, want 'service.Foo'", attrs.GRPCService)
	}
	if attrs.GRPCMethod != "BarMethod" {
		t.Errorf("GRPCMethod = %q, want 'BarMethod'", attrs.GRPCMethod)
	}
}
