// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// MySQL command types
const (
	mysqlComQuery        = 0x03
	mysqlComStmtPrepare  = 0x16
	mysqlComStmtExecute  = 0x17
	mysqlComStmtClose    = 0x19
	mysqlComPing         = 0x0e
	mysqlComQuit         = 0x01
	mysqlComInitDB       = 0x02
)

// MySQL response types
const (
	mysqlOK    = 0x00
	mysqlERR   = 0xff
	mysqlEOF   = 0xfe
)

// MySQLParser parses MySQL wire protocol.
type MySQLParser struct{}

func (p *MySQLParser) Name() string { return ProtoMySQL }

func (p *MySQLParser) Detect(data []byte, port uint16) bool {
	if len(data) < 5 {
		return false
	}

	// MySQL packet: 3-byte length + 1-byte sequence + payload
	pktLen := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
	seqID := data[3]

	// COM_QUERY: sequence=0, command=0x03
	if seqID == 0 && pktLen > 1 && pktLen < 1<<20 {
		if data[4] == mysqlComQuery || data[4] == mysqlComStmtPrepare ||
			data[4] == mysqlComStmtExecute || data[4] == mysqlComPing ||
			data[4] == mysqlComQuit || data[4] == mysqlComInitDB {
			return true
		}
	}

	// Server handshake: protocol version 0x0a
	if seqID == 0 && data[4] == 0x0a {
		return true
	}

	// Port fallback
	return port == 3306
}

func (p *MySQLParser) Parse(request, response []byte) (*SpanAttributes, error) {
	attrs := &SpanAttributes{
		Protocol:    ProtoMySQL,
		DBSystem:    "mysql",
		DBOperation: "QUERY",
	}

	// Parse request
	if len(request) >= 5 {
		pktLen := uint32(request[0]) | uint32(request[1])<<8 | uint32(request[2])<<16
		cmd := request[4]

		switch cmd {
		case mysqlComQuery:
			end := int(pktLen) + 4
			if end > len(request) {
				end = len(request)
			}
			query := string(request[5:end])
			attrs.DBStatement = query
			attrs.DBOperation = extractSQLOperation(query)

		case mysqlComStmtPrepare:
			end := int(pktLen) + 4
			if end > len(request) {
				end = len(request)
			}
			query := string(request[5:end])
			attrs.DBStatement = query
			attrs.DBOperation = "PREPARE"

		case mysqlComStmtExecute:
			attrs.DBOperation = "EXECUTE"
			// Statement ID is in bytes 5-8
			if len(request) >= 9 {
				stmtID := binary.LittleEndian.Uint32(request[5:9])
				attrs.DBStatement = fmt.Sprintf("stmt#%d", stmtID)
			}

		case mysqlComInitDB:
			end := int(pktLen) + 4
			if end > len(request) {
				end = len(request)
			}
			attrs.DBName = string(request[5:end])
			attrs.DBOperation = "USE"
			attrs.DBStatement = "USE " + attrs.DBName

		case mysqlComPing:
			attrs.DBOperation = "PING"
			attrs.DBStatement = "PING"

		case mysqlComQuit:
			attrs.DBOperation = "QUIT"
			attrs.DBStatement = "QUIT"
		}
	}

	// Parse response
	if len(response) >= 5 {
		respType := response[4]

		switch respType {
		case mysqlERR:
			attrs.Error = true
			if len(response) >= 9 {
				errCode := binary.LittleEndian.Uint16(response[5:7])
				// Skip marker byte (0x23 = '#') and SQL state (5 chars)
				msgStart := 9
				if len(response) > 9 && response[7] == '#' {
					msgStart = 13
				}
				if msgStart < len(response) {
					// Find end of packet
					pktLen := uint32(response[0]) | uint32(response[1])<<8 | uint32(response[2])<<16
					end := int(pktLen) + 4
					if end > len(response) {
						end = len(response)
					}
					attrs.ErrorMsg = fmt.Sprintf("MySQL error %d: %s", errCode, string(response[msgStart:end]))
				}
			}

		case mysqlOK:
			// OK packet - success

		default:
			// Result set (column count)
		}
	}

	// Build span name
	if attrs.DBStatement != "" {
		stmt := attrs.DBStatement
		if len(stmt) > 50 {
			stmt = stmt[:50] + "..."
		}
		attrs.Name = fmt.Sprintf("MySQL %s", stmt)
	} else {
		attrs.Name = fmt.Sprintf("MySQL %s", attrs.DBOperation)
	}

	return attrs, nil
}

// extractMySQLDB tries to extract the database name from a USE statement.
func extractMySQLDB(query string) string {
	q := strings.TrimSpace(query)
	upper := strings.ToUpper(q)
	if strings.HasPrefix(upper, "USE ") {
		db := strings.TrimSpace(q[4:])
		db = strings.Trim(db, "`\"' ;")
		return db
	}
	return ""
}
