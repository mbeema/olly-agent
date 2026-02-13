// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// mcpMethods lists all MCP JSON-RPC method prefixes and exact names.
var mcpMethodPrefixes = []string{
	"tools/",
	"resources/",
	"prompts/",
	"notifications/",
	"completion/",
	"sampling/",
	"roots/",
	"logging/",
}

var mcpMethodExact = map[string]bool{
	"initialize": true,
	"ping":       true,
}

// MCPParser parses MCP (Model Context Protocol) JSON-RPC 2.0 requests/responses
// transported over HTTP (Streamable HTTP or legacy SSE).
type MCPParser struct{}

func (p *MCPParser) Name() string { return ProtoMCP }

func (p *MCPParser) Detect(data []byte, port uint16) bool {
	return detectMCP(data)
}

func (p *MCPParser) Parse(request, response []byte) (*SpanAttributes, error) {
	attrs := &SpanAttributes{
		Protocol: ProtoMCP,
	}

	// Extract underlying HTTP attributes
	parseHTTPLine(request, attrs)
	parseHTTPResponseStatus(response, attrs)

	// Detect transport type from response headers
	if len(response) > 0 {
		ct := extractHTTPHeader(response, "Content-Type")
		if strings.Contains(ct, "text/event-stream") {
			attrs.MCPTransport = "sse"
		} else {
			attrs.MCPTransport = "streamable-http"
		}
	} else {
		attrs.MCPTransport = "streamable-http"
	}

	// Extract Mcp-Session-Id header
	if sid := extractHTTPHeader(request, "Mcp-Session-Id"); sid != "" {
		attrs.MCPSessionID = sid
	} else if len(response) > 0 {
		if sid = extractHTTPHeader(response, "Mcp-Session-Id"); sid != "" {
			attrs.MCPSessionID = sid
		}
	}

	// Parse JSON-RPC request body
	parseMCPRequest(request, attrs)

	// Parse JSON-RPC response body
	if len(response) > 0 {
		parseMCPResponse(response, attrs)
	}

	// Build span name: "{method}" or "{method} {tool/resource/prompt name}"
	attrs.Name = buildMCPSpanName(attrs)

	// Error detection from HTTP status or JSON-RPC error
	if attrs.HTTPStatusCode >= 400 {
		attrs.Error = true
		attrs.ErrorMsg = fmt.Sprintf("HTTP %d", attrs.HTTPStatusCode)
	} else if attrs.MCPErrorCode != 0 {
		attrs.Error = true
		if attrs.MCPErrorMsg != "" {
			attrs.ErrorMsg = fmt.Sprintf("JSON-RPC %d: %s", attrs.MCPErrorCode, attrs.MCPErrorMsg)
		} else {
			attrs.ErrorMsg = fmt.Sprintf("JSON-RPC %d", attrs.MCPErrorCode)
		}
	}

	return attrs, nil
}

// detectMCP checks if an HTTP request body contains MCP JSON-RPC 2.0 content.
// Used by Refine() to promote "http" → "mcp".
func detectMCP(data []byte) bool {
	if len(data) < 10 {
		return false
	}

	// Must be a POST request (MCP Streamable HTTP uses POST for JSON-RPC)
	if !bytes.HasPrefix(data, []byte("POST ")) {
		return false
	}

	body := extractHTTPBody(data)
	if len(body) == 0 {
		return false
	}

	// Must contain JSON-RPC 2.0 marker
	if !bytes.Contains(body, []byte(`"jsonrpc"`)) {
		return false
	}

	// Must have an MCP-specific method
	method := extractJSONString(body, "method")
	return isMCPMethod(method)
}

// isMCPMethod checks if a JSON-RPC method name is an MCP method.
func isMCPMethod(method string) bool {
	if method == "" {
		return false
	}
	if mcpMethodExact[method] {
		return true
	}
	for _, prefix := range mcpMethodPrefixes {
		if strings.HasPrefix(method, prefix) {
			return true
		}
	}
	return false
}

// parseMCPRequest extracts JSON-RPC fields from the MCP request body.
func parseMCPRequest(request []byte, attrs *SpanAttributes) {
	body := extractHTTPBody(request)
	if len(body) == 0 {
		return
	}

	// JSON-RPC method
	if v := extractJSONString(body, "method"); v != "" {
		attrs.MCPMethod = v
	}

	// JSON-RPC id (can be string or number)
	if v := extractJSONString(body, "id"); v != "" {
		attrs.MCPRequestID = v
	} else if v := extractJSONNumber(body, "id"); v != "" {
		attrs.MCPRequestID = v
	}

	// Extract method-specific params
	switch {
	case attrs.MCPMethod == "tools/call":
		// params.name = tool name
		if v := extractNestedJSONString(body, "params", "name"); v != "" {
			attrs.MCPToolName = v
		}
	case attrs.MCPMethod == "resources/read" || attrs.MCPMethod == "resources/subscribe":
		// params.uri = resource URI
		if v := extractNestedJSONString(body, "params", "uri"); v != "" {
			attrs.MCPResourceURI = v
		}
	case attrs.MCPMethod == "prompts/get":
		// params.name = prompt name
		if v := extractNestedJSONString(body, "params", "name"); v != "" {
			attrs.MCPPromptName = v
		}
	}
}

// parseMCPResponse extracts JSON-RPC result or error from the MCP response body.
func parseMCPResponse(response []byte, attrs *SpanAttributes) {
	body := extractHTTPBody(response)
	if len(body) == 0 {
		return
	}

	// Check for JSON-RPC error
	// Pattern: "error":{"code":-32600,"message":"Invalid Request"}
	if bytes.Contains(body, []byte(`"error"`)) {
		if v := extractNestedJSONNumber(body, "error", "code"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				attrs.MCPErrorCode = n
			}
		}
		if v := extractNestedJSONString(body, "error", "message"); v != "" {
			attrs.MCPErrorMsg = v
		}
	}
}

// buildMCPSpanName creates a descriptive span name from MCP attributes.
func buildMCPSpanName(attrs *SpanAttributes) string {
	method := attrs.MCPMethod
	if method == "" {
		return "mcp"
	}

	switch {
	case method == "tools/call" && attrs.MCPToolName != "":
		return fmt.Sprintf("tools/call %s", attrs.MCPToolName)
	case method == "resources/read" && attrs.MCPResourceURI != "":
		uri := attrs.MCPResourceURI
		// Truncate long URIs for span name
		if len(uri) > 50 {
			uri = uri[:50] + "..."
		}
		return fmt.Sprintf("resources/read %s", uri)
	case method == "prompts/get" && attrs.MCPPromptName != "":
		return fmt.Sprintf("prompts/get %s", attrs.MCPPromptName)
	default:
		return method
	}
}

// extractNestedJSONString extracts a string value from a nested JSON object.
// Looks for pattern: "outer":{..."inner":"value"...}
// This is a best-effort byte-level extraction for truncation tolerance.
func extractNestedJSONString(data []byte, outer, inner string) string {
	// Find the outer key
	outerNeedle := []byte(`"` + outer + `"`)
	idx := bytes.Index(data, outerNeedle)
	if idx < 0 {
		return ""
	}

	// Find the opening brace of the nested object
	rest := data[idx+len(outerNeedle):]
	rest = bytes.TrimLeft(rest, " \t\n\r")
	if len(rest) == 0 || rest[0] != ':' {
		return ""
	}
	rest = rest[1:]
	rest = bytes.TrimLeft(rest, " \t\n\r")

	if len(rest) == 0 || rest[0] != '{' {
		return ""
	}

	// Extract the inner value from the nested object
	return extractJSONString(rest, inner)
}

// extractNestedJSONNumber extracts a number value from a nested JSON object.
func extractNestedJSONNumber(data []byte, outer, inner string) string {
	outerNeedle := []byte(`"` + outer + `"`)
	idx := bytes.Index(data, outerNeedle)
	if idx < 0 {
		return ""
	}

	rest := data[idx+len(outerNeedle):]
	rest = bytes.TrimLeft(rest, " \t\n\r")
	if len(rest) == 0 || rest[0] != ':' {
		return ""
	}
	rest = rest[1:]
	rest = bytes.TrimLeft(rest, " \t\n\r")

	if len(rest) == 0 || rest[0] != '{' {
		return ""
	}

	return extractJSONNumber(rest, inner)
}
