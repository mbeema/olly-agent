// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// MongoDB wire protocol op codes
const (
	mongoOpMsg   = 2013
	mongoOpQuery = 2004
	mongoOpReply = 1
)

// MongoDBParser parses MongoDB wire protocol.
type MongoDBParser struct{}

func (p *MongoDBParser) Name() string { return ProtoMongoDB }

func (p *MongoDBParser) Detect(data []byte, port uint16) bool {
	if len(data) < 16 {
		return false
	}

	// MongoDB wire protocol: 4-byte length, 4-byte requestID, 4-byte responseTo, 4-byte opCode
	msgLen := binary.LittleEndian.Uint32(data[0:4])
	opCode := binary.LittleEndian.Uint32(data[12:16])

	// Sanity check message length
	if msgLen < 16 || msgLen > 48*1024*1024 { // 48MB max
		return false
	}

	switch opCode {
	case mongoOpMsg, mongoOpQuery, mongoOpReply:
		return true
	}

	// Port fallback
	return port == 27017
}

func (p *MongoDBParser) Parse(request, response []byte) (*SpanAttributes, error) {
	attrs := &SpanAttributes{
		Protocol:    ProtoMongoDB,
		DBSystem:    "mongodb",
		DBOperation: "command",
	}

	if len(request) >= 20 {
		opCode := binary.LittleEndian.Uint32(request[12:16])

		switch opCode {
		case mongoOpMsg:
			p.parseOpMsg(request[16:], attrs)
		case mongoOpQuery:
			p.parseOpQuery(request[16:], attrs)
		}
	}

	// Check response for errors
	if len(response) >= 20 {
		opCode := binary.LittleEndian.Uint32(response[12:16])
		if opCode == mongoOpMsg {
			p.checkOpMsgError(response[16:], attrs)
		}
	}

	// Mark admin-only commands with no specific operation as handshake noise.
	// These are typically topology monitoring, session management, etc.
	if attrs.DBOperation == "command" {
		attrs.Handshake = true
	}

	// Build span name (OTEL: "{operation} {collection}")
	if attrs.DBTable != "" {
		attrs.Name = fmt.Sprintf("%s %s", attrs.DBOperation, attrs.DBTable)
	} else {
		attrs.Name = attrs.DBOperation
	}

	return attrs, nil
}

func (p *MongoDBParser) parseOpMsg(data []byte, attrs *SpanAttributes) {
	if len(data) < 5 {
		return
	}

	// OP_MSG: flagBits(4) + sections
	// Section kind 0: single BSON document
	offset := 4 // skip flagBits

	if offset >= len(data) {
		return
	}

	kind := data[offset]
	offset++

	if kind == 0 {
		// Body section: single BSON document
		p.extractCommandFromBSON(data[offset:], attrs)
	}
}

func (p *MongoDBParser) parseOpQuery(data []byte, attrs *SpanAttributes) {
	if len(data) < 12 {
		return
	}

	// OP_QUERY: flags(4) + fullCollectionName(cstring) + numberToSkip(4) + numberToReturn(4) + query(BSON)
	offset := 4 // skip flags

	// Read collection name (null-terminated)
	nameEnd := offset
	for nameEnd < len(data) && data[nameEnd] != 0 {
		nameEnd++
	}

	if nameEnd > offset {
		fullName := string(data[offset:nameEnd])
		parts := strings.SplitN(fullName, ".", 2)
		if len(parts) >= 1 {
			attrs.DBName = parts[0] // database name → db.namespace
		}
		if len(parts) >= 2 {
			// Collection is after the dot
			if parts[1] == "$cmd" {
				attrs.DBOperation = "command"
			} else {
				attrs.DBOperation = "find"
				attrs.DBTable = parts[1] // collection → db.collection.name
				attrs.DBStatement = fullName
			}
		}
	}
}

// extractCommandFromBSON does a basic extraction of the command name from BSON.
// It reads the first element key as the command name and scans for $db to set DBName.
func (p *MongoDBParser) extractCommandFromBSON(data []byte, attrs *SpanAttributes) {
	if len(data) < 5 {
		return
	}

	// BSON: int32 size + elements + \x00
	// Element: type(1) + name(cstring) + value
	offset := 4 // skip size

	if offset >= len(data) || data[offset] == 0 {
		return
	}

	firstKey := true
	for offset < len(data) && data[offset] != 0 {
		elemType := data[offset]
		offset++

		// Read element name (null-terminated)
		nameEnd := offset
		for nameEnd < len(data) && data[nameEnd] != 0 {
			nameEnd++
		}
		if nameEnd <= offset || nameEnd >= len(data) {
			break
		}

		name := string(data[offset:nameEnd])
		offset = nameEnd + 1

		if firstKey {
			firstKey = false
			// The first key in the command document is the command name
			cmd := strings.ToLower(name)
			attrs.DBOperation = cmd

			// Mark handshake/admin commands that don't represent user queries
			switch cmd {
			case "ismaster", "hello", "saslstart", "saslcontinue", "authenticate",
				"getnonce", "buildinfo", "getlasterror", "ping", "endsessions",
				"abortTransaction", "commitTransaction":
				attrs.Handshake = true
			}

			// Extract collection name from command value (string type)
			// This is the collection/table name (e.g., "find" → "reviews")
			if elemType == 0x02 && offset+4 < len(data) {
				strLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
				if strLen > 0 && strLen < 256 && offset+4+strLen <= len(data) {
					val := string(data[offset+4 : offset+4+strLen-1]) // -1 for null terminator
					if val != "" && val != "1" && val != "admin" {
						attrs.DBTable = val // collection name → db.collection.name
						attrs.DBStatement = fmt.Sprintf("%s %s", cmd, val)
					}
				}
			}
		}

		// Look for $db field (standard in OP_MSG commands) → db.namespace
		if name == "$db" && elemType == 0x02 && offset+4 < len(data) {
			strLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
			if strLen > 0 && strLen < 256 && offset+4+strLen <= len(data) {
				db := string(data[offset+4 : offset+4+strLen-1])
				if db != "" {
					attrs.DBName = db // database name → db.namespace
				}
				// Mark admin database commands as handshake
				if db == "admin" && attrs.DBTable == "" {
					attrs.Handshake = true
				}
			}
		}

		// Skip value based on type to advance to next element
		offset = skipBSONValue(data, offset, elemType)
		if offset < 0 || offset >= len(data) {
			break
		}
	}
}

// skipBSONValue advances past a BSON value of the given type.
// Returns the new offset, or -1 if the value can't be skipped.
func skipBSONValue(data []byte, offset int, elemType byte) int {
	switch elemType {
	case 0x01: // double (8 bytes)
		return offset + 8
	case 0x02: // string (int32 length + string + \x00)
		if offset+4 > len(data) {
			return -1
		}
		strLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		return offset + 4 + strLen
	case 0x03, 0x04: // document, array (int32 size + content)
		if offset+4 > len(data) {
			return -1
		}
		docLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if docLen < 5 {
			return -1
		}
		return offset + docLen
	case 0x05: // binary (int32 length + subtype + data)
		if offset+4 > len(data) {
			return -1
		}
		binLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		return offset + 4 + 1 + binLen
	case 0x07: // ObjectId (12 bytes)
		return offset + 12
	case 0x08: // boolean (1 byte)
		return offset + 1
	case 0x09: // datetime (8 bytes)
		return offset + 8
	case 0x0A: // null (0 bytes)
		return offset
	case 0x10: // int32 (4 bytes)
		return offset + 4
	case 0x11: // timestamp (8 bytes)
		return offset + 8
	case 0x12: // int64 (8 bytes)
		return offset + 8
	default:
		return -1 // unknown type, can't skip
	}
}

func (p *MongoDBParser) checkOpMsgError(data []byte, attrs *SpanAttributes) {
	// Simple check: look for "ok" field with value 0 in response BSON
	if len(data) < 10 {
		return
	}

	// Look for "ok" : 0.0 pattern (BSON double)
	idx := findBSONField(data, "ok")
	if idx < 0 {
		return
	}

	// Check if value is 0
	if idx+9 <= len(data) && data[idx] == 0x01 { // double type
		offset := idx + 3 + 1 // skip type + "ok\x00"
		if offset+8 <= len(data) {
			val := binary.LittleEndian.Uint64(data[offset : offset+8])
			if val == 0 {
				attrs.Error = true
				attrs.ErrorMsg = "MongoDB command failed"
			}
		}
	}
}

// findBSONField returns the offset of a BSON element with the given name.
func findBSONField(data []byte, fieldName string) int {
	needle := append([]byte(fieldName), 0)
	for i := 4; i < len(data)-len(needle); i++ {
		if data[i] == needle[0] {
			match := true
			for j := 1; j < len(needle); j++ {
				if i+j >= len(data) || data[i+j] != needle[j] {
					match = false
					break
				}
			}
			if match {
				return i - 1 // return position of type byte
			}
		}
	}
	return -1
}
