// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"testing"
)

func TestMCPDetect(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		expect bool
	}{
		{
			name: "tools/call",
			data: "POST /mcp HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n" +
				`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather"}}`,
			expect: true,
		},
		{
			name: "tools/list",
			data: "POST /mcp HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n" +
				`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
			expect: true,
		},
		{
			name: "initialize",
			data: "POST /mcp HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n" +
				`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`,
			expect: true,
		},
		{
			name: "resources/read",
			data: "POST /mcp HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n" +
				`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///data.csv"}}`,
			expect: true,
		},
		{
			name: "prompts/get",
			data: "POST /mcp HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n" +
				`{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"code_review"}}`,
			expect: true,
		},
		{
			name: "ping",
			data: "POST /mcp HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n" +
				`{"jsonrpc":"2.0","id":5,"method":"ping"}`,
			expect: true,
		},
		{
			name: "notifications/initialized",
			data: "POST /mcp HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n" +
				`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			expect: true,
		},
		{
			name: "sampling/createMessage",
			data: "POST /mcp HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n" +
				`{"jsonrpc":"2.0","id":6,"method":"sampling/createMessage","params":{}}`,
			expect: true,
		},
		{
			name:   "regular HTTP GET - not MCP",
			data:   "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expect: false,
		},
		{
			name: "regular POST with JSON body - not MCP",
			data: "POST /api/orders HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n" +
				`{"name":"test","quantity":1}`,
			expect: false,
		},
		{
			name: "JSON-RPC but non-MCP method",
			data: "POST /rpc HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n" +
				`{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":["0xabc"]}`,
			expect: false,
		},
		{
			name: "GenAI endpoint - not MCP",
			data: "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n" +
				`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`,
			expect: false,
		},
		{
			name:   "too short",
			data:   "POST",
			expect: false,
		},
		{
			name:   "empty",
			data:   "",
			expect: false,
		},
	}

	parser := &MCPParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.Detect([]byte(tt.data), 0)
			if got != tt.expect {
				t.Errorf("Detect() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestMCPParseToolsCall(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"Mcp-Session-Id: sess-abc-123\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"San Francisco"}}}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Mcp-Session-Id: sess-abc-123\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"72F, sunny"}]}}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.Protocol != ProtoMCP {
		t.Errorf("Protocol = %q, want %q", attrs.Protocol, ProtoMCP)
	}
	if attrs.MCPMethod != "tools/call" {
		t.Errorf("MCPMethod = %q, want %q", attrs.MCPMethod, "tools/call")
	}
	if attrs.MCPRequestID != "1" {
		t.Errorf("MCPRequestID = %q, want %q", attrs.MCPRequestID, "1")
	}
	if attrs.MCPToolName != "get_weather" {
		t.Errorf("MCPToolName = %q, want %q", attrs.MCPToolName, "get_weather")
	}
	if attrs.MCPSessionID != "sess-abc-123" {
		t.Errorf("MCPSessionID = %q, want %q", attrs.MCPSessionID, "sess-abc-123")
	}
	if attrs.MCPTransport != "streamable-http" {
		t.Errorf("MCPTransport = %q, want %q", attrs.MCPTransport, "streamable-http")
	}
	if attrs.Name != "tools/call get_weather" {
		t.Errorf("Name = %q, want %q", attrs.Name, "tools/call get_weather")
	}
	if attrs.HTTPMethod != "POST" {
		t.Errorf("HTTPMethod = %q, want POST", attrs.HTTPMethod)
	}
	if attrs.HTTPStatusCode != 200 {
		t.Errorf("HTTPStatusCode = %d, want 200", attrs.HTTPStatusCode)
	}
	if attrs.Error {
		t.Error("Error should be false for 200 response")
	}
	if attrs.MCPToolContentType != "text" {
		t.Errorf("MCPToolContentType = %q, want %q", attrs.MCPToolContentType, "text")
	}
}

func TestMCPParseResourcesRead(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///data.csv"}}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":3,"result":{"contents":[{"uri":"file:///data.csv","text":"col1,col2\n1,2"}]}}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPMethod != "resources/read" {
		t.Errorf("MCPMethod = %q, want %q", attrs.MCPMethod, "resources/read")
	}
	if attrs.MCPResourceURI != "file:///data.csv" {
		t.Errorf("MCPResourceURI = %q, want %q", attrs.MCPResourceURI, "file:///data.csv")
	}
	if attrs.Name != "resources/read file:///data.csv" {
		t.Errorf("Name = %q, want %q", attrs.Name, "resources/read file:///data.csv")
	}
}

func TestMCPParsePromptsGet(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":4,"method":"prompts/get","params":{"name":"code_review","arguments":{"language":"go"}}}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), nil)
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPMethod != "prompts/get" {
		t.Errorf("MCPMethod = %q, want %q", attrs.MCPMethod, "prompts/get")
	}
	if attrs.MCPPromptName != "code_review" {
		t.Errorf("MCPPromptName = %q, want %q", attrs.MCPPromptName, "code_review")
	}
	if attrs.Name != "prompts/get code_review" {
		t.Errorf("Name = %q, want %q", attrs.Name, "prompts/get code_review")
	}
}

func TestMCPParseInitialize(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{}}}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Mcp-Session-Id: sess-new-456\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"my-mcp-server","version":"1.2.3"},"capabilities":{"tools":{}}}}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPMethod != "initialize" {
		t.Errorf("MCPMethod = %q, want %q", attrs.MCPMethod, "initialize")
	}
	if attrs.MCPSessionID != "sess-new-456" {
		t.Errorf("MCPSessionID = %q, want %q (from response header)", attrs.MCPSessionID, "sess-new-456")
	}
	if attrs.Name != "initialize" {
		t.Errorf("Name = %q, want %q", attrs.Name, "initialize")
	}
	if attrs.MCPProtocolVersion != "2025-03-26" {
		t.Errorf("MCPProtocolVersion = %q, want %q", attrs.MCPProtocolVersion, "2025-03-26")
	}
	if attrs.MCPServerName != "my-mcp-server" {
		t.Errorf("MCPServerName = %q, want %q", attrs.MCPServerName, "my-mcp-server")
	}
	if attrs.MCPServerVersion != "1.2.3" {
		t.Errorf("MCPServerVersion = %q, want %q", attrs.MCPServerVersion, "1.2.3")
	}
}

func TestMCPParseJSONRPCError(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"missing_tool"}}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPErrorCode != -32601 {
		t.Errorf("MCPErrorCode = %d, want -32601", attrs.MCPErrorCode)
	}
	if attrs.MCPErrorMsg != "Method not found" {
		t.Errorf("MCPErrorMsg = %q, want %q", attrs.MCPErrorMsg, "Method not found")
	}
	if !attrs.Error {
		t.Error("Error should be true for JSON-RPC error")
	}
	if attrs.ErrorMsg != "JSON-RPC -32601: Method not found" {
		t.Errorf("ErrorMsg = %q, want %q", attrs.ErrorMsg, "JSON-RPC -32601: Method not found")
	}
}

func TestMCPParseHTTPError(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"}}`

	response := "HTTP/1.1 500 Internal Server Error\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"error":"internal server error"}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.HTTPStatusCode != 500 {
		t.Errorf("HTTPStatusCode = %d, want 500", attrs.HTTPStatusCode)
	}
	if !attrs.Error {
		t.Error("Error should be true for 500")
	}
}

func TestMCPParseSSETransport(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/event-stream\r\n" +
		"\r\n" +
		`data: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"test"}]}}` + "\n\n"

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPTransport != "sse" {
		t.Errorf("MCPTransport = %q, want %q", attrs.MCPTransport, "sse")
	}
}

func TestMCPParseNotification(t *testing.T) {
	// Notifications have no "id" field
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), nil)
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPMethod != "notifications/initialized" {
		t.Errorf("MCPMethod = %q, want %q", attrs.MCPMethod, "notifications/initialized")
	}
	if attrs.MCPRequestID != "" {
		t.Errorf("MCPRequestID = %q, want empty (notification)", attrs.MCPRequestID)
	}
	if attrs.Name != "notifications/initialized" {
		t.Errorf("Name = %q, want %q", attrs.Name, "notifications/initialized")
	}
}

func TestMCPParseTruncated(t *testing.T) {
	// Simulate eBPF MAX_CAPTURE=256 truncation
	fullRequest := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"Mcp-Session-Id: sess-very-long-id-12345\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_weather","arguments":{"location":"San Francisco, CA, USA","unit":"fahrenheit","include_forecast":true}}}`

	truncated := fullRequest
	if len(truncated) > 256 {
		truncated = truncated[:256]
	}

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(truncated), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Method should be extractable from truncated data
	if attrs.MCPMethod != "tools/call" {
		t.Errorf("MCPMethod = %q, want %q (from truncated data)", attrs.MCPMethod, "tools/call")
	}
	// Tool name should also fit within 256 bytes
	if attrs.MCPToolName != "get_weather" {
		t.Errorf("MCPToolName = %q, want %q (from truncated data)", attrs.MCPToolName, "get_weather")
	}
}

func TestMCPParseStringID(t *testing.T) {
	// JSON-RPC id can be a string
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":"req-abc-123","method":"tools/call","params":{"name":"test"}}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), nil)
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPRequestID != "req-abc-123" {
		t.Errorf("MCPRequestID = %q, want %q", attrs.MCPRequestID, "req-abc-123")
	}
}

func TestMCPParseNumericID(t *testing.T) {
	// JSON-RPC id as a number (no quotes)
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":42,"method":"tools/list"}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), nil)
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPRequestID != "42" {
		t.Errorf("MCPRequestID = %q, want %q", attrs.MCPRequestID, "42")
	}
}

func TestMCPRefine(t *testing.T) {
	mcpRequest := "POST /mcp HTTP/1.1\r\nHost: localhost:3000\r\nContent-Type: application/json\r\n\r\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test"}}`
	regularRequest := "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"
	genaiRequest := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n"

	// HTTP + MCP body → mcp
	if got := Refine("http", []byte(mcpRequest), 80); got != "mcp" {
		t.Errorf("Refine(http, mcp) = %q, want %q", got, "mcp")
	}

	// HTTP + regular endpoint → stays http
	if got := Refine("http", []byte(regularRequest), 80); got != "http" {
		t.Errorf("Refine(http, regular) = %q, want %q", got, "http")
	}

	// HTTP + GenAI → genai (GenAI takes priority)
	if got := Refine("http", []byte(genaiRequest), 443); got != "genai" {
		t.Errorf("Refine(http, genai) = %q, want %q", got, "genai")
	}

	// Non-HTTP → unchanged
	if got := Refine("postgres", []byte(mcpRequest), 5432); got != "postgres" {
		t.Errorf("Refine(postgres, mcp) = %q, want %q", got, "postgres")
	}
}

func TestMCPNoDoubleRegister(t *testing.T) {
	// Verify MCP isn't in the main registry (it uses Refine instead)
	for _, p := range registry {
		if p.Name() == ProtoMCP {
			t.Error("MCPParser should NOT be in registry (uses Refine, not Detect)")
		}
	}
}

func TestMCPIsMCPMethod(t *testing.T) {
	tests := []struct {
		method string
		expect bool
	}{
		{"initialize", true},
		{"ping", true},
		{"tools/call", true},
		{"tools/list", true},
		{"resources/read", true},
		{"resources/list", true},
		{"resources/subscribe", true},
		{"prompts/get", true},
		{"prompts/list", true},
		{"notifications/initialized", true},
		{"notifications/cancelled", true},
		{"sampling/createMessage", true},
		{"completion/complete", true},
		{"roots/list", true},
		{"logging/setLevel", true},
		{"eth_getBalance", false},
		{"getUser", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			if got := isMCPMethod(tt.method); got != tt.expect {
				t.Errorf("isMCPMethod(%q) = %v, want %v", tt.method, got, tt.expect)
			}
		})
	}
}

func TestMCPParseEmptyBody(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"\r\n"

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), nil)
	if err != nil {
		t.Fatal(err)
	}

	// No body → no method, but should not crash
	if attrs.MCPMethod != "" {
		t.Errorf("MCPMethod = %q, want empty", attrs.MCPMethod)
	}
	if attrs.Name != "mcp" {
		t.Errorf("Name = %q, want %q", attrs.Name, "mcp")
	}
}

func TestExtractNestedJSONString(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		outer  string
		inner  string
		expect string
	}{
		{
			name:   "tool name",
			data:   `{"params":{"name":"get_weather","arguments":{}}}`,
			outer:  "params",
			inner:  "name",
			expect: "get_weather",
		},
		{
			name:   "resource URI",
			data:   `{"params":{"uri":"file:///data.csv"}}`,
			outer:  "params",
			inner:  "uri",
			expect: "file:///data.csv",
		},
		{
			name:   "missing outer",
			data:   `{"other":{"name":"test"}}`,
			outer:  "params",
			inner:  "name",
			expect: "",
		},
		{
			name:   "missing inner",
			data:   `{"params":{"other":"value"}}`,
			outer:  "params",
			inner:  "name",
			expect: "",
		},
		{
			name:   "nested with spaces",
			data:   `{"params" : { "name" : "spaced_tool" }}`,
			outer:  "params",
			inner:  "name",
			expect: "spaced_tool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNestedJSONString([]byte(tt.data), tt.outer, tt.inner)
			if got != tt.expect {
				t.Errorf("extractNestedJSONString(%q, %q) = %q, want %q", tt.outer, tt.inner, got, tt.expect)
			}
		})
	}
}

func TestExtractNestedJSONNumber(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		outer  string
		inner  string
		expect string
	}{
		{
			name:   "error code",
			data:   `{"error":{"code":-32601,"message":"Method not found"}}`,
			outer:  "error",
			inner:  "code",
			expect: "-32601",
		},
		{
			name:   "missing",
			data:   `{"result":{"value":42}}`,
			outer:  "error",
			inner:  "code",
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNestedJSONNumber([]byte(tt.data), tt.outer, tt.inner)
			if got != tt.expect {
				t.Errorf("extractNestedJSONNumber(%q, %q) = %q, want %q", tt.outer, tt.inner, got, tt.expect)
			}
		})
	}
}

func TestMCPParseToolsList(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"get_weather"},{"name":"search"},{"name":"calculate"}]}}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPMethod != "tools/list" {
		t.Errorf("MCPMethod = %q, want %q", attrs.MCPMethod, "tools/list")
	}
	if attrs.MCPToolsCount != 3 {
		t.Errorf("MCPToolsCount = %d, want 3", attrs.MCPToolsCount)
	}
}

func TestMCPParseToolsCallError(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"flaky_tool"}}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"error occurred"}],"isError":true}}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if !attrs.MCPToolIsError {
		t.Error("MCPToolIsError should be true")
	}
	if attrs.MCPToolContentType != "text" {
		t.Errorf("MCPToolContentType = %q, want %q", attrs.MCPToolContentType, "text")
	}
}

func TestMCPParseResourcesReadMimeType(t *testing.T) {
	request := "POST /mcp HTTP/1.1\r\n" +
		"Host: localhost:3000\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///report.csv"}}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"jsonrpc":"2.0","id":3,"result":{"contents":[{"uri":"file:///report.csv","mimeType":"text/csv","text":"a,b\n1,2"}]}}`

	parser := &MCPParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.MCPResourceMimeType != "text/csv" {
		t.Errorf("MCPResourceMimeType = %q, want %q", attrs.MCPResourceMimeType, "text/csv")
	}
}

func TestExtractDeepJSONString(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		l1, l2, l3 string
		expect string
	}{
		{
			name:   "server info name",
			data:   `{"result":{"serverInfo":{"name":"my-server","version":"1.0"}}}`,
			l1: "result", l2: "serverInfo", l3: "name",
			expect: "my-server",
		},
		{
			name:   "server info version",
			data:   `{"result":{"serverInfo":{"name":"srv","version":"2.1.0"}}}`,
			l1: "result", l2: "serverInfo", l3: "version",
			expect: "2.1.0",
		},
		{
			name:   "missing middle level",
			data:   `{"result":{"protocolVersion":"2025-03-26"}}`,
			l1: "result", l2: "serverInfo", l3: "name",
			expect: "",
		},
		{
			name:   "missing inner key",
			data:   `{"result":{"serverInfo":{"name":"srv"}}}`,
			l1: "result", l2: "serverInfo", l3: "version",
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDeepJSONString([]byte(tt.data), tt.l1, tt.l2, tt.l3)
			if got != tt.expect {
				t.Errorf("extractDeepJSONString(%q, %q, %q) = %q, want %q", tt.l1, tt.l2, tt.l3, got, tt.expect)
			}
		})
	}
}

func TestCountJSONArrayElements(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		key    string
		expect int
	}{
		{
			name:   "three tools",
			data:   `{"tools":[{"name":"a"},{"name":"b"},{"name":"c"}]}`,
			key:    "tools",
			expect: 3,
		},
		{
			name:   "one tool",
			data:   `{"tools":[{"name":"only"}]}`,
			key:    "tools",
			expect: 1,
		},
		{
			name:   "empty array",
			data:   `{"tools":[]}`,
			key:    "tools",
			expect: 0,
		},
		{
			name:   "missing key",
			data:   `{"result":{}}`,
			key:    "tools",
			expect: 0,
		},
		{
			name:   "nested arrays in elements",
			data:   `{"tools":[{"name":"a","args":["x","y"]},{"name":"b"}]}`,
			key:    "tools",
			expect: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := countJSONArrayElements([]byte(tt.data), tt.key)
			if got != tt.expect {
				t.Errorf("countJSONArrayElements(%q) = %d, want %d", tt.key, got, tt.expect)
			}
		})
	}
}

func TestExtractNestedJSONBool(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		outer  string
		inner  string
		expect string
	}{
		{
			name:   "isError true",
			data:   `{"result":{"content":[],"isError":true}}`,
			outer:  "result",
			inner:  "isError",
			expect: "true",
		},
		{
			name:   "isError false",
			data:   `{"result":{"content":[],"isError":false}}`,
			outer:  "result",
			inner:  "isError",
			expect: "false",
		},
		{
			name:   "missing",
			data:   `{"result":{"content":[]}}`,
			outer:  "result",
			inner:  "isError",
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNestedJSONBool([]byte(tt.data), tt.outer, tt.inner)
			if got != tt.expect {
				t.Errorf("extractNestedJSONBool(%q, %q) = %q, want %q", tt.outer, tt.inner, got, tt.expect)
			}
		})
	}
}

func TestExtractNestedArrayFirstString(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		arrayKey string
		fieldKey string
		expect   string
	}{
		{
			name:     "content type text",
			data:     `{"content":[{"type":"text","text":"hello"}]}`,
			arrayKey: "content",
			fieldKey: "type",
			expect:   "text",
		},
		{
			name:     "content type image",
			data:     `{"content":[{"type":"image","data":"base64..."},{"type":"text","text":"cap"}]}`,
			arrayKey: "content",
			fieldKey: "type",
			expect:   "image",
		},
		{
			name:     "contents mimeType",
			data:     `{"contents":[{"uri":"file:///a.csv","mimeType":"text/csv","text":"data"}]}`,
			arrayKey: "contents",
			fieldKey: "mimeType",
			expect:   "text/csv",
		},
		{
			name:     "empty array",
			data:     `{"content":[]}`,
			arrayKey: "content",
			fieldKey: "type",
			expect:   "",
		},
		{
			name:     "missing key",
			data:     `{"other":[{"type":"text"}]}`,
			arrayKey: "content",
			fieldKey: "type",
			expect:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNestedArrayFirstString([]byte(tt.data), tt.arrayKey, tt.fieldKey)
			if got != tt.expect {
				t.Errorf("extractNestedArrayFirstString(%q, %q) = %q, want %q", tt.arrayKey, tt.fieldKey, got, tt.expect)
			}
		})
	}
}
