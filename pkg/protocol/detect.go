// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"strings"
)

// Protocol names.
const (
	ProtoHTTP     = "http"
	ProtoPostgres = "postgres"
	ProtoMySQL    = "mysql"
	ProtoRedis    = "redis"
	ProtoMongoDB  = "mongodb"
	ProtoGRPC     = "grpc"
	ProtoDNS      = "dns"
	ProtoGenAI    = "genai"
	ProtoMCP      = "mcp"
	ProtoUnknown  = "unknown"
)

// SpanAttributes holds parsed protocol attributes for span generation.
type SpanAttributes struct {
	Protocol string
	Name     string // span name (e.g., "GET /api/users", "SELECT", "GET key")

	// HTTP
	HTTPMethod     string
	HTTPPath       string
	HTTPQuery      string // query string without '?' prefix
	HTTPStatusCode int
	HTTPHost       string
	HTTPUserAgent  string
	ContentLength  int64

	// Database
	DBSystem    string
	DBStatement string
	DBOperation string
	DBTable     string // table/collection name extracted from query
	DBName      string
	DBUser      string

	// Redis
	RedisCommand string
	RedisArgs    string

	// gRPC
	GRPCService string
	GRPCMethod  string
	GRPCStatus  int

	// DNS
	DNSName    string
	DNSType    string
	DNSRcode   string
	DNSAnswers int

	// GenAI (OTEL gen_ai.* semantic conventions)
	GenAIProvider      string  // e.g., "openai", "anthropic", "aws.bedrock"
	GenAIOperation     string  // e.g., "chat", "text_completion", "embeddings"
	GenAIRequestModel  string  // model from request
	GenAIResponseModel string  // model from response (may differ)
	GenAIResponseID    string  // response ID (e.g., "chatcmpl-...")
	GenAIInputTokens   int     // prompt/input tokens
	GenAIOutputTokens  int     // completion/output tokens
	GenAIInputTokensSet  bool  // true if input tokens were parsed
	GenAIOutputTokensSet bool  // true if output tokens were parsed
	GenAIFinishReason  string  // e.g., "stop", "end_turn", "length"
	GenAITemperature   float64
	GenAITemperatureSet bool
	GenAITopP          float64
	GenAITopPSet       bool
	GenAIMaxTokens     int
	GenAIMaxTokensSet  bool
	GenAIStreaming      bool   // true if SSE streaming response

	// MCP (Model Context Protocol - JSON-RPC 2.0 over HTTP)
	MCPMethod      string // JSON-RPC method (e.g., "tools/call", "resources/read")
	MCPRequestID   string // JSON-RPC request ID
	MCPToolName    string // Tool name for tools/call
	MCPResourceURI string // Resource URI for resources/read
	MCPPromptName  string // Prompt name for prompts/get
	MCPSessionID   string // Mcp-Session-Id header
	MCPErrorCode   int    // JSON-RPC error code
	MCPErrorMsg    string // JSON-RPC error message
	MCPTransport        string // "streamable-http" or "sse"
	MCPProtocolVersion  string // From initialize response result.protocolVersion
	MCPServerName       string // From initialize response result.serverInfo.name
	MCPServerVersion    string // From initialize response result.serverInfo.version
	MCPToolsCount       int    // Count of tools in tools/list response result.tools[]
	MCPToolIsError      bool   // From tools/call response result.isError
	MCPToolContentType  string // First content[].type from tools/call response
	MCPResourceMimeType string // First contents[].mimeType from resources/read response

	// General
	Error      bool
	ErrorMsg   string
	Handshake  bool // true for connection handshake/admin commands (skip span)
}

// ProtocolParser extracts span attributes from request/response byte buffers.
type ProtocolParser interface {
	// Name returns the protocol name.
	Name() string

	// Detect checks if the data matches this protocol.
	Detect(data []byte, port uint16) bool

	// Parse extracts attributes from a request/response pair.
	Parse(request, response []byte) (*SpanAttributes, error)
}

// registry holds all registered protocol parsers.
var registry []ProtocolParser

func init() {
	// Order matters: more specific protocols first
	registry = []ProtocolParser{
		&GRPCParser{},
		&HTTPParser{},
		&PostgresParser{},
		&MySQLParser{},
		&RedisParser{},
		&MongoDBParser{},
		&DNSParser{},
	}
}

// Detect identifies the protocol from data and port.
func Detect(data []byte, port uint16) string {
	for _, p := range registry {
		if p.Detect(data, port) {
			return p.Name()
		}
	}
	return ProtoUnknown
}

// genaiParser is kept outside the Detect registry (GenAI is detected via
// Refine, not Detect) but must be reachable from Parse.
var genaiParser = &GenAIParser{}

// mcpParser is kept outside the Detect registry (MCP is detected via
// Refine, not Detect) but must be reachable from Parse.
var mcpParser = &MCPParser{}

// Parse uses the appropriate parser to extract span attributes.
func Parse(proto string, request, response []byte) (*SpanAttributes, error) {
	// GenAI and MCP use Refine() instead of Detect(), so they're not in the registry.
	if proto == ProtoGenAI {
		return genaiParser.Parse(request, response)
	}
	if proto == ProtoMCP {
		return mcpParser.Parse(request, response)
	}
	for _, p := range registry {
		if p.Name() == proto {
			return p.Parse(request, response)
		}
	}

	return &SpanAttributes{
		Protocol: ProtoUnknown,
		Name:     "unknown",
	}, nil
}

// DetectAndParse detects the protocol and parses in one step.
func DetectAndParse(request, response []byte, port uint16) (*SpanAttributes, error) {
	proto := Detect(request, port)
	return Parse(proto, request, response)
}

// isHTTPMethod checks if the string starts with an HTTP method.
func isHTTPMethod(s string) bool {
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "CONNECT ", "TRACE "}
	for _, m := range methods {
		if strings.HasPrefix(s, m) {
			return true
		}
	}
	return false
}
