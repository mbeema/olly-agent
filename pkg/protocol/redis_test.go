// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"testing"
)

func TestRedisDetect(t *testing.T) {
	p := &RedisParser{}

	tests := []struct {
		name   string
		data   []byte
		port   uint16
		expect bool
	}{
		{"RESP array", []byte("*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n"), 0, true},
		{"Simple string", []byte("+OK\r\n"), 0, true},
		{"Error", []byte("-ERR unknown command\r\n"), 0, true},
		{"Integer", []byte(":42\r\n"), 0, true},
		{"Bulk string", []byte("$3\r\nfoo\r\n"), 0, true},
		{"Not RESP", []byte("Hello World"), 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := p.Detect(tt.data, tt.port)
			if got != tt.expect {
				t.Errorf("Detect(%q, %d) = %v, want %v", tt.data, tt.port, got, tt.expect)
			}
		})
	}
}

func TestRedisParse(t *testing.T) {
	p := &RedisParser{}

	request := []byte("*2\r\n$3\r\nGET\r\n$7\r\nsession\r\n")
	response := []byte("$5\r\nhello\r\n")

	attrs, err := p.Parse(request, response)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if attrs.RedisCommand != "GET" {
		t.Errorf("command = %q, want GET", attrs.RedisCommand)
	}
	if attrs.Name != "GET session" {
		t.Errorf("name = %q, want 'GET session'", attrs.Name)
	}
	if attrs.Error {
		t.Error("unexpected error")
	}
}

func TestRedisParseError(t *testing.T) {
	p := &RedisParser{}

	request := []byte("*1\r\n$4\r\nPING\r\n")
	response := []byte("-ERR connection refused\r\n")

	attrs, err := p.Parse(request, response)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if !attrs.Error {
		t.Error("expected error")
	}
	if attrs.ErrorMsg != "ERR connection refused" {
		t.Errorf("errorMsg = %q", attrs.ErrorMsg)
	}
}
