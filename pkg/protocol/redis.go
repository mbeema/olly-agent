// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"bytes"
	"strconv"
	"strings"
)

// RedisParser parses Redis RESP protocol.
type RedisParser struct{}

func (p *RedisParser) Name() string { return ProtoRedis }

func (p *RedisParser) Detect(data []byte, port uint16) bool {
	if len(data) < 3 {
		return false
	}

	// RESP protocol markers
	first := data[0]
	switch first {
	case '*': // Array (command)
		return isRESPNumber(data[1:])
	case '+': // Simple string
		return bytes.Contains(data[:min(len(data), 32)], []byte("\r\n"))
	case '-': // Error
		return bytes.Contains(data[:min(len(data), 64)], []byte("\r\n"))
	case '$': // Bulk string
		return isRESPNumber(data[1:])
	case ':': // Integer
		return isRESPNumber(data[1:])
	}

	// Inline command (e.g., "PING\r\n")
	if port == 6379 {
		line := data[:min(len(data), 32)]
		if bytes.Contains(line, []byte("\r\n")) {
			cmd := strings.ToUpper(string(line[:bytes.Index(line, []byte("\r\n"))]))
			return isRedisCommand(cmd)
		}
	}

	return false
}

func (p *RedisParser) Parse(request, response []byte) (*SpanAttributes, error) {
	attrs := &SpanAttributes{
		Protocol: ProtoRedis,
		DBSystem: "redis",
	}

	// Parse RESP command
	if len(request) > 0 {
		cmd, args := parseRESPCommand(request)
		attrs.RedisCommand = strings.ToUpper(cmd)
		attrs.RedisArgs = args
		attrs.DBOperation = attrs.RedisCommand
		attrs.DBStatement = attrs.RedisCommand
		if args != "" {
			attrs.DBStatement += " " + args
		}
	}

	// Parse response for errors
	if len(response) > 0 && response[0] == '-' {
		attrs.Error = true
		end := bytes.Index(response, []byte("\r\n"))
		if end > 0 {
			attrs.ErrorMsg = string(response[1:end])
		}
	}

	// Build span name (OTEL: low-cardinality, use command only)
	if attrs.RedisCommand != "" {
		attrs.Name = attrs.RedisCommand
	} else {
		attrs.Name = "REDIS"
	}

	return attrs, nil
}

// parseRESPCommand parses a RESP array into command and args.
func parseRESPCommand(data []byte) (cmd, args string) {
	if len(data) < 3 {
		return "", ""
	}

	// Inline command
	if data[0] != '*' {
		end := bytes.Index(data, []byte("\r\n"))
		if end < 0 {
			end = len(data)
		}
		parts := strings.Fields(string(data[:end]))
		if len(parts) == 0 {
			return "", ""
		}
		return parts[0], strings.Join(parts[1:], " ")
	}

	// RESP array: *<count>\r\n$<len>\r\n<data>\r\n...
	parts := parseRESPArray(data)
	if len(parts) == 0 {
		return "", ""
	}

	return parts[0], strings.Join(parts[1:], " ")
}

// parseRESPArray extracts string elements from a RESP array.
func parseRESPArray(data []byte) []string {
	if len(data) < 4 || data[0] != '*' {
		return nil
	}

	// Get array count
	end := bytes.Index(data, []byte("\r\n"))
	if end < 0 {
		return nil
	}
	count, err := strconv.Atoi(string(data[1:end]))
	if err != nil || count <= 0 || count > 100 {
		return nil
	}

	offset := end + 2
	var parts []string

	for i := 0; i < count && offset < len(data); i++ {
		if data[offset] != '$' {
			break
		}

		// Get bulk string length
		end = bytes.Index(data[offset:], []byte("\r\n"))
		if end < 0 {
			break
		}
		strLen, err := strconv.Atoi(string(data[offset+1 : offset+end]))
		if err != nil || strLen < 0 {
			break
		}
		offset += end + 2

		if offset+strLen > len(data) {
			break
		}

		parts = append(parts, string(data[offset:offset+strLen]))
		offset += strLen + 2 // skip \r\n
	}

	return parts
}

func isRESPNumber(data []byte) bool {
	if len(data) < 2 {
		return false
	}
	for i, b := range data {
		if b == '\r' {
			return i > 0
		}
		if b < '0' || b > '9' {
			if i == 0 && b == '-' {
				continue
			}
			return false
		}
	}
	return false
}

func isRedisCommand(cmd string) bool {
	cmds := map[string]bool{
		"PING": true, "GET": true, "SET": true, "DEL": true,
		"MGET": true, "MSET": true, "HGET": true, "HSET": true,
		"LPUSH": true, "RPUSH": true, "LPOP": true, "RPOP": true,
		"SADD": true, "SMEMBERS": true, "ZADD": true, "ZRANGE": true,
		"SUBSCRIBE": true, "PUBLISH": true, "AUTH": true, "SELECT": true,
		"INFO": true, "KEYS": true, "SCAN": true, "TTL": true,
		"EXPIRE": true, "INCR": true, "DECR": true,
	}
	return cmds[cmd]
}
