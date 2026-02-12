// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"testing"
)

func TestDetect(t *testing.T) {
	tests := []struct {
		name   string
		data   []byte
		port   uint16
		expect string
	}{
		{"HTTP GET", []byte("GET / HTTP/1.1\r\n"), 80, ProtoHTTP},
		{"HTTP POST", []byte("POST /api HTTP/1.1\r\n"), 8080, ProtoHTTP},
		{"Redis RESP", []byte("*2\r\n$3\r\nGET\r\n$3\r\nfoo\r\n"), 6379, ProtoRedis},
		{"PostgreSQL query", []byte{'Q', 0, 0, 0, 14, 'S', 'E', 'L', 'E', 'C', 'T', ' ', '1', 0}, 5432, ProtoPostgres},
		{"MySQL on port", []byte{0x05, 0x00, 0x00, 0x00, 0x03}, 3306, ProtoMySQL},
		{"DNS query", makeDNSQuery("example.com"), 53, ProtoDNS},
		{"gRPC preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 50051, ProtoGRPC},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Detect(tt.data, tt.port)
			if got != tt.expect {
				t.Errorf("Detect() = %q, want %q", got, tt.expect)
			}
		})
	}
}

// makeDNSQuery creates a minimal DNS query for testing.
func makeDNSQuery(name string) []byte {
	// DNS header: ID, flags (standard query), 1 question, 0 answers, 0 authority, 0 additional
	header := []byte{
		0x12, 0x34, // ID
		0x01, 0x00, // Flags: standard query, recursion desired
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answers: 0
		0x00, 0x00, // Authority: 0
		0x00, 0x00, // Additional: 0
	}

	// Question section
	question := encodeDNSName(name)
	question = append(question, 0x00, 0x01) // Type A
	question = append(question, 0x00, 0x01) // Class IN

	return append(header, question...)
}

func encodeDNSName(name string) []byte {
	var result []byte
	for _, label := range splitDNSName(name) {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0) // root label
	return result
}

func splitDNSName(name string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	labels = append(labels, name[start:])
	return labels
}
