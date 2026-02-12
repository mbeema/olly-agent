// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"encoding/binary"
	"testing"
)

// buildPgMsg builds a PostgreSQL wire protocol message: type(1) + len(4) + payload
func buildPgMsg(msgType byte, payload []byte) []byte {
	msg := make([]byte, 5+len(payload))
	msg[0] = msgType
	binary.BigEndian.PutUint32(msg[1:5], uint32(4+len(payload)))
	copy(msg[5:], payload)
	return msg
}

// buildCString builds a null-terminated string
func buildCString(s string) []byte {
	b := make([]byte, len(s)+1)
	copy(b, s)
	b[len(s)] = 0
	return b
}

func TestPostgresSimpleQuery(t *testing.T) {
	p := &PostgresParser{}

	query := "SELECT * FROM users WHERE id = 1"
	payload := buildCString(query)
	request := buildPgMsg('Q', payload)

	attrs, err := p.Parse(request, nil)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if attrs.DBStatement != query {
		t.Errorf("DBStatement = %q, want %q", attrs.DBStatement, query)
	}
	if attrs.DBOperation != "SELECT" {
		t.Errorf("DBOperation = %q, want SELECT", attrs.DBOperation)
	}
	if attrs.DBSystem != "postgresql" {
		t.Errorf("DBSystem = %q, want postgresql", attrs.DBSystem)
	}
}

func TestPostgresExtendedQuery(t *testing.T) {
	p := &PostgresParser{}

	// Build Parse message: P + len + stmtName\0 + query\0 + 0(int16 param count)
	stmtName := buildCString("stmt1")
	queryStr := buildCString("INSERT INTO orders (user_id, amount) VALUES ($1, $2)")
	parsePayload := append(stmtName, queryStr...)
	parsePayload = append(parsePayload, 0, 0) // 0 params
	parseMsg := buildPgMsg('P', parsePayload)

	// Build Bind message: B + len + portal\0 + stmtName\0 + ...
	portalName := buildCString("")
	bindStmt := buildCString("stmt1")
	bindPayload := append(portalName, bindStmt...)
	bindPayload = append(bindPayload, 0, 0) // 0 format codes
	bindPayload = append(bindPayload, 0, 0) // 0 params
	bindPayload = append(bindPayload, 0, 0) // 0 result format codes
	bindMsg := buildPgMsg('B', bindPayload)

	// Build Execute message: E + len + portal\0 + maxrows(int32)
	execPayload := append(buildCString(""), 0, 0, 0, 0) // unnamed portal, 0 max rows
	execMsg := buildPgMsg('E', execPayload)

	// Build Sync: S + len(4)
	syncMsg := buildPgMsg('S', nil)

	// Concatenate all messages
	request := append(parseMsg, bindMsg...)
	request = append(request, execMsg...)
	request = append(request, syncMsg...)

	attrs, err := p.Parse(request, nil)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	expectedSQL := "INSERT INTO orders (user_id, amount) VALUES ($1, $2)"
	if attrs.DBStatement != expectedSQL {
		t.Errorf("DBStatement = %q, want %q", attrs.DBStatement, expectedSQL)
	}
	if attrs.DBOperation != "INSERT" {
		t.Errorf("DBOperation = %q, want INSERT", attrs.DBOperation)
	}
}

func TestPostgresPreparedStatementCache(t *testing.T) {
	p := &PostgresParser{}

	// First request: Parse a named statement
	stmtName := buildCString("myquery")
	queryStr := buildCString("SELECT name FROM products WHERE id = $1")
	parsePayload := append(stmtName, queryStr...)
	parsePayload = append(parsePayload, 0, 0)
	parseMsg := buildPgMsg('P', parsePayload)

	syncMsg := buildPgMsg('S', nil)
	request1 := append(parseMsg, syncMsg...)

	// Parse first request (caches the statement)
	_, err := p.Parse(request1, nil)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// Second request: Bind+Execute using the cached statement (no Parse)
	portalName := buildCString("")
	bindStmt := buildCString("myquery")
	bindPayload := append(portalName, bindStmt...)
	bindPayload = append(bindPayload, 0, 0, 0, 0, 0, 0)
	bindMsg := buildPgMsg('B', bindPayload)

	execPayload := append(buildCString(""), 0, 0, 0, 0)
	execMsg := buildPgMsg('E', execPayload)

	request2 := append(bindMsg, execMsg...)
	request2 = append(request2, syncMsg...)

	attrs, err := p.Parse(request2, nil)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	expectedSQL := "SELECT name FROM products WHERE id = $1"
	if attrs.DBStatement != expectedSQL {
		t.Errorf("DBStatement = %q, want %q (from cached prepared statement)", attrs.DBStatement, expectedSQL)
	}
	if attrs.DBOperation != "SELECT" {
		t.Errorf("DBOperation = %q, want SELECT", attrs.DBOperation)
	}
}

func TestPostgresDetect(t *testing.T) {
	p := &PostgresParser{}

	// Simple query
	payload := buildCString("SELECT 1")
	msg := buildPgMsg('Q', payload)
	if !p.Detect(msg, 0) {
		t.Error("should detect simple query")
	}

	// Parse message
	parseMsg := buildPgMsg('P', buildCString(""))
	if !p.Detect(parseMsg, 0) {
		t.Error("should detect Parse message")
	}

	// Port fallback
	if !p.Detect([]byte("random"), 5432) {
		t.Error("should detect on port 5432")
	}

	// Startup message
	startup := make([]byte, 12)
	binary.BigEndian.PutUint32(startup[0:4], 12)
	binary.BigEndian.PutUint32(startup[4:8], 0x00030000) // version 3.0
	if !p.Detect(startup, 0) {
		t.Error("should detect startup message")
	}
}

func TestPostgresErrorResponse(t *testing.T) {
	p := &PostgresParser{}

	request := buildPgMsg('Q', buildCString("SELECT * FROM nonexistent"))

	// Build ErrorResponse: E + len + fields
	// Field: type(1 byte) + value(cstring), terminated by 0 byte
	var errPayload []byte
	errPayload = append(errPayload, 'S') // Severity
	errPayload = append(errPayload, buildCString("ERROR")...)
	errPayload = append(errPayload, 'M') // Message
	errPayload = append(errPayload, buildCString("relation \"nonexistent\" does not exist")...)
	errPayload = append(errPayload, 0) // terminator
	response := buildPgMsg('E', errPayload)

	attrs, err := p.Parse(request, response)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if !attrs.Error {
		t.Error("expected Error=true")
	}
	if attrs.ErrorMsg != "relation \"nonexistent\" does not exist" {
		t.Errorf("ErrorMsg = %q", attrs.ErrorMsg)
	}
}
