// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package redact

import (
	"testing"
)

func TestRedactCreditCard(t *testing.T) {
	r := New(true, nil)
	tests := []struct {
		input    string
		expected string
	}{
		{"card: 4111111111111111", "card: [REDACTED_CC]"},
		{"card: 4111-1111-1111-1111", "card: [REDACTED_CC]"},
		{"card: 5500 0000 0000 0004", "card: [REDACTED_CC]"},
		{"no card here", "no card here"},
	}
	for _, tt := range tests {
		got := r.Redact(tt.input)
		if got != tt.expected {
			t.Errorf("Redact(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestRedactSSN(t *testing.T) {
	r := New(true, nil)
	input := "ssn: 123-45-6789"
	got := r.Redact(input)
	if got != "ssn: [REDACTED_SSN]" {
		t.Errorf("Redact(%q) = %q", input, got)
	}
}

func TestRedactAuthorizationHeader(t *testing.T) {
	r := New(true, nil)
	tests := []struct {
		input string
		want  string
	}{
		{"Authorization: Bearer abc123", "Authorization: [REDACTED]"},
		{"authorization: token xyz", "authorization: [REDACTED]"},
	}
	for _, tt := range tests {
		got := r.Redact(tt.input)
		if got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRedactPassword(t *testing.T) {
	r := New(true, nil)
	tests := []struct {
		input string
		want  string
	}{
		{"password=secret123", "password=[REDACTED]"},
		{"api_key=abc-def-123", "api_key=[REDACTED]"},
	}
	for _, tt := range tests {
		got := r.Redact(tt.input)
		if got != tt.want {
			t.Errorf("Redact(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRedactDisabled(t *testing.T) {
	r := New(false, nil)
	input := "card: 4111111111111111"
	got := r.Redact(input)
	if got != input {
		t.Errorf("disabled Redact should return input unchanged, got %q", got)
	}
}

func TestRedactMap(t *testing.T) {
	r := New(true, nil)
	attrs := map[string]string{
		"db.query.text": "SELECT * WHERE password='secret'",
		"url.path":      "/api/users",
	}
	r.RedactMap(attrs, "db.query.text")
	if attrs["db.query.text"] == "SELECT * WHERE password='secret'" {
		t.Error("expected db.query.text to be redacted")
	}
	if attrs["url.path"] != "/api/users" {
		t.Error("url.path should be unchanged")
	}
}

func TestRedactHeaders(t *testing.T) {
	headers := "Authorization: Bearer token123\r\nContent-Type: application/json\r\nCookie: session=abc"
	got := RedactHeaders(headers)
	if got != "Authorization: [REDACTED]\r\nContent-Type: application/json\r\nCookie: [REDACTED]" {
		t.Errorf("RedactHeaders = %q", got)
	}
}
