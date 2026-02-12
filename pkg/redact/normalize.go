// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package redact

import (
	"regexp"
)

var (
	// String literals: 'value' or "value"
	singleQuotedStr = regexp.MustCompile(`'[^']*'`)
	doubleQuotedStr = regexp.MustCompile(`"[^"]*"`)

	// Numeric literals (integers and decimals, including negative)
	numericLiteral = regexp.MustCompile(`\b-?\d+(?:\.\d+)?\b`)

	// Hex values like 0xABCD
	hexLiteral = regexp.MustCompile(`\b0x[0-9a-fA-F]+\b`)

	// IN lists: IN (1, 2, 3) or IN ('a', 'b') — only after the IN keyword
	inList = regexp.MustCompile(`(?i)\bIN\s*\([^)]+\)`)

)

// NormalizeSQL replaces literal values in SQL queries with '?' placeholders.
// This prevents high-cardinality span attributes while preserving query structure.
func NormalizeSQL(query string) string {
	if query == "" {
		return query
	}

	// 1. Replace IN lists first (before individual values)
	result := inList.ReplaceAllString(query, "IN (?)")

	// 2. Replace hex literals
	result = hexLiteral.ReplaceAllString(result, "?")

	// 3. Replace string literals
	result = singleQuotedStr.ReplaceAllString(result, "?")
	result = doubleQuotedStr.ReplaceAllString(result, "?")

	// 4. Replace numeric literals
	result = numericLiteral.ReplaceAllString(result, "?")

	return result
}
