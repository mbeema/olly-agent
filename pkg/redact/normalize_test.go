// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package redact

import (
	"testing"
)

func TestNormalizeSQL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "select with string literal",
			input:    "SELECT * FROM users WHERE name = 'john'",
			expected: "SELECT * FROM users WHERE name = ?",
		},
		{
			name:     "select with numeric",
			input:    "SELECT * FROM users WHERE id = 42",
			expected: "SELECT * FROM users WHERE id = ?",
		},
		{
			name:     "insert with values",
			input:    "INSERT INTO users (name, age) VALUES ('alice', 30)",
			expected: "INSERT INTO users (name, age) VALUES (?, ?)",
		},
		{
			name:     "IN list",
			input:    "SELECT * FROM users WHERE id IN (1, 2, 3, 4)",
			expected: "SELECT * FROM users WHERE id IN (?)",
		},
		{
			name:     "hex value",
			input:    "SELECT * FROM data WHERE hash = 0xDEADBEEF",
			expected: "SELECT * FROM data WHERE hash = ?",
		},
		{
			name:     "update with set",
			input:    "UPDATE users SET name = 'bob', age = 25 WHERE id = 1",
			expected: "UPDATE users SET name = ?, age = ? WHERE id = ?",
		},
		{
			name:     "empty query",
			input:    "",
			expected: "",
		},
		{
			name:     "query with no literals",
			input:    "SELECT * FROM users",
			expected: "SELECT * FROM users",
		},
		{
			name:     "decimal numbers",
			input:    "SELECT * FROM prices WHERE amount > 19.99",
			expected: "SELECT * FROM prices WHERE amount > ?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeSQL(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeSQL(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
