// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"encoding/binary"
	"strings"
	"sync"
)

// PostgreSQL wire protocol message types
const (
	pgQuery         = 'Q'
	pgParse         = 'P'
	pgBind          = 'B'
	pgDescribe      = 'D'
	pgExecute       = 'E'
	pgSync          = 'S'
	pgClose         = 'C'
	pgRowDesc       = 'T'
	pgDataRow       = 'D'
	pgCommandComp   = 'C'
	pgErrorResponse = 'E'
	pgReadyForQuery = 'Z'
	pgParseComplete = '1'
	pgBindComplete  = '2'
	pgCloseComplete = '3'
)

// PostgresParser parses PostgreSQL wire protocol.
// H7 fix: Tracks Parse→Bind→Execute lifecycle for extended query protocol.
type PostgresParser struct {
	// Track prepared statements: name → SQL query
	mu         sync.RWMutex
	stmtCache  map[string]string // statement name → SQL
	portalCache map[string]string // portal name → statement name
}

func (p *PostgresParser) Name() string { return ProtoPostgres }

func (p *PostgresParser) Detect(data []byte, port uint16) bool {
	if len(data) < 5 {
		return false
	}

	// Simple Query protocol: 'Q' followed by 4-byte length
	if data[0] == pgQuery {
		msgLen := binary.BigEndian.Uint32(data[1:5])
		if msgLen > 4 && msgLen < 1<<20 { // sanity check: < 1MB
			return true
		}
	}

	// Parse (extended query): 'P' followed by 4-byte length
	if data[0] == pgParse || data[0] == pgBind || data[0] == pgExecute {
		msgLen := binary.BigEndian.Uint32(data[1:5])
		if msgLen > 4 && msgLen < 1<<20 {
			return true
		}
	}

	// Startup message (no type byte, starts with length + version)
	if len(data) >= 8 {
		msgLen := binary.BigEndian.Uint32(data[0:4])
		version := binary.BigEndian.Uint32(data[4:8])
		// Version 3.0 = 0x00030000
		if version == 0x00030000 && msgLen > 8 && msgLen < 1024 {
			return true
		}
	}

	// Port fallback
	if port == 5432 {
		return true
	}

	return false
}

func (p *PostgresParser) Parse(request, response []byte) (*SpanAttributes, error) {
	attrs := &SpanAttributes{
		Protocol:    ProtoPostgres,
		DBSystem:    "postgresql",
		DBOperation: "QUERY",
	}

	// B5 fix: clear caches before each parse to prevent cross-connection
	// statement pollution. The per-call local variables handle the common
	// Parse+Bind+Execute-in-same-buffer case. CommandComplete in the response
	// provides the operation when cached SQL is unavailable.
	p.mu.Lock()
	p.stmtCache = nil
	p.portalCache = nil
	p.mu.Unlock()

	// Walk all messages in the request buffer.
	// Extended query sends Parse + Bind + Describe + Execute + Sync in sequence.
	p.parseExtendedQuery(request, attrs)

	// Parse response
	if len(response) >= 5 {
		p.parseResponse(response, attrs)
	}

	// Extract table name and build span name per OTEL: "{operation} {table}"
	attrs.DBTable = extractSQLTable(attrs.DBStatement)
	if attrs.DBTable != "" {
		attrs.Name = attrs.DBOperation + " " + attrs.DBTable
	} else {
		attrs.Name = attrs.DBOperation
	}

	return attrs, nil
}

// parseExtendedQuery walks through all frontend messages and tracks
// Parse→Bind→Execute lifecycle.
func (p *PostgresParser) parseExtendedQuery(data []byte, attrs *SpanAttributes) {
	if len(data) < 5 {
		return
	}

	// Track what we find in this request buffer
	var lastParsedStmt string
	var lastParsedSQL string
	var lastBoundStmt string

	offset := 0
	for offset+5 <= len(data) {
		msgType := data[offset]
		msgLen := binary.BigEndian.Uint32(data[offset+1 : offset+5])

		if msgLen < 4 || offset+1+int(msgLen) > len(data) {
			break
		}

		payload := data[offset+5 : offset+1+int(msgLen)]

		switch msgType {
		case pgQuery:
			// Simple query: extract SQL directly
			query := extractCString(payload)
			attrs.DBStatement = query
			attrs.DBOperation = extractSQLOperation(query)
			return // Simple query mode, no need to continue

		case pgParse:
			// Parse: name(cstring) + query(cstring) + numparams(int16) + param types
			stmtName := extractCString(payload)
			if len(stmtName)+1 > len(payload) {
				break // C3 fix: truncated message, no null terminator
			}
			remaining := payload[len(stmtName)+1:]
			query := extractCString(remaining)

			lastParsedStmt = stmtName
			lastParsedSQL = query

			// Cache for future Execute messages
			p.cacheStatement(stmtName, query)

			// If this is unnamed, it's the query for this batch
			if attrs.DBStatement == "" {
				attrs.DBStatement = query
				attrs.DBOperation = extractSQLOperation(query)
			}

		case pgBind:
			// Bind: portal(cstring) + statement(cstring) + ...
			portalName := extractCString(payload)
			if len(portalName)+1 > len(payload) {
				break // C3 fix: truncated message
			}
			remaining := payload[len(portalName)+1:]
			stmtName := extractCString(remaining)

			lastBoundStmt = stmtName

			// Cache portal→statement mapping
			p.cachePortal(portalName, stmtName)

			// If the statement was just parsed in this batch, use its SQL
			if stmtName == lastParsedStmt && lastParsedSQL != "" {
				attrs.DBStatement = lastParsedSQL
				attrs.DBOperation = extractSQLOperation(lastParsedSQL)
			} else if sql := p.lookupStatement(stmtName); sql != "" {
				attrs.DBStatement = sql
				attrs.DBOperation = extractSQLOperation(sql)
			}

		case pgExecute:
			// Execute: portal(cstring) + max_rows(int32)
			portalName := extractCString(payload)

			// Try to find the SQL for this portal
			if attrs.DBStatement == "" {
				stmtName := p.lookupPortal(portalName)
				if stmtName == "" {
					stmtName = lastBoundStmt
				}
				if stmtName == lastParsedStmt && lastParsedSQL != "" {
					attrs.DBStatement = lastParsedSQL
					attrs.DBOperation = extractSQLOperation(lastParsedSQL)
				} else if sql := p.lookupStatement(stmtName); sql != "" {
					attrs.DBStatement = sql
					attrs.DBOperation = extractSQLOperation(sql)
				}
			}

		case pgDescribe:
			// Describe: type('S' or 'P') + name(cstring) - skip

		case pgSync:
			// Sync message - end of extended query batch

		case 'C': // Close
			// Close: type('S' or 'P') + name(cstring)
			if len(payload) > 0 {
				closeType := payload[0]
				name := extractCString(payload[1:])
				if closeType == 'S' {
					p.removeStatement(name)
				} else if closeType == 'P' {
					p.removePortal(name)
				}
			}
		}

		offset += 1 + int(msgLen)
	}
}

func (p *PostgresParser) parseResponse(data []byte, attrs *SpanAttributes) {
	offset := 0
	for offset+5 <= len(data) {
		msgType := data[offset]
		msgLen := binary.BigEndian.Uint32(data[offset+1 : offset+5])

		if msgLen < 4 || offset+1+int(msgLen) > len(data) {
			break
		}

		switch msgType {
		case 'C': // CommandComplete
			end := offset + 5 + int(msgLen) - 4
			if end > len(data) {
				end = len(data)
			}
			tag := string(data[offset+5 : end])
			if idx := strings.IndexByte(tag, 0); idx >= 0 {
				tag = tag[:idx]
			}
			// Tag is like "SELECT 100" or "INSERT 0 1"
			if attrs.DBOperation == "QUERY" {
				parts := strings.Fields(tag)
				if len(parts) > 0 {
					attrs.DBOperation = parts[0]
				}
			}

		case 'E': // ErrorResponse
			attrs.Error = true
			// Parse error fields
			payload := data[offset+5:]
			maxEnd := offset + 1 + int(msgLen)
			if maxEnd > len(data) {
				maxEnd = len(data)
			}
			payload = data[offset+5 : maxEnd]

			for i := 0; i < len(payload)-1; {
				fieldType := payload[i]
				i++
				end := i
				for end < len(payload) && payload[end] != 0 {
					end++
				}
				value := string(payload[i:end])
				i = end + 1

				if fieldType == 'M' { // Message
					attrs.ErrorMsg = value
					break
				}
				if fieldType == 0 {
					break
				}
			}
		}

		offset += 1 + int(msgLen)
	}
}

// Statement cache operations

// maxCacheSize limits the prepared statement cache to prevent memory leaks
// from long-running connections that prepare many unique statements.
const maxCacheSize = 1000

func (p *PostgresParser) cacheStatement(name, sql string) {
	if name == "" {
		return // unnamed statements are transient
	}
	p.mu.Lock()
	if p.stmtCache == nil {
		p.stmtCache = make(map[string]string)
	}
	if len(p.stmtCache) >= maxCacheSize {
		// Evict an arbitrary entry to stay within bounds
		for k := range p.stmtCache {
			delete(p.stmtCache, k)
			break
		}
	}
	p.stmtCache[name] = sql
	p.mu.Unlock()
}

func (p *PostgresParser) lookupStatement(name string) string {
	p.mu.RLock()
	sql := p.stmtCache[name]
	p.mu.RUnlock()
	return sql
}

func (p *PostgresParser) removeStatement(name string) {
	p.mu.Lock()
	delete(p.stmtCache, name)
	p.mu.Unlock()
}

func (p *PostgresParser) cachePortal(portal, stmt string) {
	p.mu.Lock()
	if p.portalCache == nil {
		p.portalCache = make(map[string]string)
	}
	if len(p.portalCache) >= maxCacheSize {
		for k := range p.portalCache {
			delete(p.portalCache, k)
			break
		}
	}
	p.portalCache[portal] = stmt
	p.mu.Unlock()
}

func (p *PostgresParser) lookupPortal(portal string) string {
	p.mu.RLock()
	stmt := p.portalCache[portal]
	p.mu.RUnlock()
	return stmt
}

func (p *PostgresParser) removePortal(portal string) {
	p.mu.Lock()
	delete(p.portalCache, portal)
	p.mu.Unlock()
}

// extractCString extracts a null-terminated string from a byte slice.
func extractCString(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

// extractSQLTable extracts the target table name from a SQL statement.
// Used for OTEL span naming: "{operation} {table}".
func extractSQLTable(query string) string {
	query = strings.TrimSpace(query)
	if len(query) == 0 {
		return ""
	}

	upper := strings.ToUpper(query)
	words := strings.Fields(query)
	upperWords := strings.Fields(upper)

	if len(upperWords) < 2 {
		return ""
	}

	switch upperWords[0] {
	case "SELECT", "DELETE":
		// SELECT ... FROM table / DELETE FROM table
		for i, w := range upperWords {
			if w == "FROM" && i+1 < len(words) {
				return cleanTableName(words[i+1])
			}
		}
	case "INSERT":
		// INSERT INTO table
		if len(upperWords) >= 3 && upperWords[1] == "INTO" {
			return cleanTableName(words[2])
		}
	case "UPDATE":
		// UPDATE table SET ...
		return cleanTableName(words[1])
	case "CREATE", "DROP", "ALTER", "TRUNCATE":
		// CREATE TABLE table / DROP TABLE table / ALTER TABLE table
		if len(upperWords) >= 3 && (upperWords[1] == "TABLE" || upperWords[1] == "INDEX") {
			name := words[2]
			// Handle IF EXISTS / IF NOT EXISTS
			if strings.ToUpper(name) == "IF" && len(words) >= 5 {
				return cleanTableName(words[4])
			}
			return cleanTableName(name)
		}
	}

	return ""
}

// cleanTableName strips schema prefix, quotes, and parentheses from a table name.
func cleanTableName(name string) string {
	// Remove trailing parentheses, commas, semicolons
	name = strings.TrimRight(name, "(,;")
	// Remove quotes
	name = strings.Trim(name, "`\"'")
	// Take only the table part from schema.table
	if idx := strings.LastIndex(name, "."); idx >= 0 {
		name = name[idx+1:]
	}
	return name
}

func extractSQLOperation(query string) string {
	query = strings.TrimSpace(query)
	if len(query) == 0 {
		return "QUERY"
	}

	// Get first word (uppercase)
	end := strings.IndexAny(query, " \t\r\n(")
	if end < 0 {
		end = len(query)
	}
	op := strings.ToUpper(query[:end])

	switch op {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALTER",
		"BEGIN", "COMMIT", "ROLLBACK", "COPY", "TRUNCATE", "EXPLAIN", "ANALYZE",
		"SET", "SHOW", "LISTEN", "NOTIFY", "PREPARE", "DEALLOCATE":
		return op
	}

	return "QUERY"
}
