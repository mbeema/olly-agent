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

// GenAI provider endpoint definitions.
type genaiEndpoint struct {
	Host      string // exact match or suffix match with "*." prefix
	Path      string // exact prefix match or contains "*" for wildcard
	Provider  string
	Operation string
}

var genaiEndpoints = []genaiEndpoint{
	// OpenAI
	{Host: "api.openai.com", Path: "/v1/chat/completions", Provider: "openai", Operation: "chat"},
	{Host: "api.openai.com", Path: "/v1/completions", Provider: "openai", Operation: "text_completion"},
	{Host: "api.openai.com", Path: "/v1/embeddings", Provider: "openai", Operation: "embeddings"},
	// Anthropic
	{Host: "api.anthropic.com", Path: "/v1/messages", Provider: "anthropic", Operation: "chat"},
	// Cohere
	{Host: "api.cohere.ai", Path: "/v1/chat", Provider: "cohere", Operation: "chat"},
	{Host: "api.cohere.ai", Path: "/v2/chat", Provider: "cohere", Operation: "chat"},
	// Mistral
	{Host: "api.mistral.ai", Path: "/v1/chat/completions", Provider: "mistral_ai", Operation: "chat"},
	// Ollama
	{Host: "localhost:11434", Path: "/api/chat", Provider: "ollama", Operation: "chat"},
	{Host: "localhost:11434", Path: "/api/generate", Provider: "ollama", Operation: "chat"},
}

// GenAIParser parses GenAI LLM API requests/responses (OpenAI, Anthropic, etc.).
type GenAIParser struct{}

func (p *GenAIParser) Name() string { return ProtoGenAI }

func (p *GenAIParser) Detect(data []byte, port uint16) bool {
	_, _, ok := detectGenAI(data)
	return ok
}

func (p *GenAIParser) Parse(request, response []byte) (*SpanAttributes, error) {
	attrs := &SpanAttributes{
		Protocol: ProtoGenAI,
	}

	// Detect provider and operation from request
	provider, operation, ok := detectGenAI(request)
	if !ok {
		return attrs, nil
	}
	attrs.GenAIProvider = provider
	attrs.GenAIOperation = operation

	// Parse request body for model and parameters
	parseGenAIRequest(request, attrs)

	// Parse response for model, tokens, finish reason
	if len(response) > 0 {
		parseGenAIResponse(response, attrs)
	}

	// Also extract underlying HTTP attributes
	parseHTTPLine(request, attrs)
	parseHTTPResponseStatus(response, attrs)

	// Build span name: "{operation} {model}"
	model := attrs.GenAIResponseModel
	if model == "" {
		model = attrs.GenAIRequestModel
	}
	if model != "" {
		attrs.Name = fmt.Sprintf("%s %s", operation, model)
	} else {
		attrs.Name = operation
	}

	// Error detection from HTTP status
	if attrs.HTTPStatusCode >= 400 {
		attrs.Error = true
		attrs.ErrorMsg = fmt.Sprintf("HTTP %d", attrs.HTTPStatusCode)
	}

	return attrs, nil
}

// detectGenAI checks if HTTP request data targets a known GenAI endpoint.
// Returns (provider, operation, true) if detected, or ("", "", false).
func detectGenAI(data []byte) (string, string, bool) {
	if len(data) < 10 {
		return "", "", false
	}

	// Must be a POST request
	if !bytes.HasPrefix(data, []byte("POST ")) {
		return "", "", false
	}

	// Extract path from request line: "POST /path HTTP/1.1\r\n"
	lineEnd := bytes.Index(data, []byte("\r\n"))
	if lineEnd < 0 {
		return "", "", false
	}
	requestLine := string(data[:lineEnd])
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return "", "", false
	}
	path := parts[1]

	// Extract Host header
	host := extractHTTPHeader(data, "Host")

	// Check against known endpoints (exact match)
	for _, ep := range genaiEndpoints {
		if host == ep.Host && strings.HasPrefix(path, ep.Path) {
			return ep.Provider, ep.Operation, true
		}
	}

	// AWS Bedrock: bedrock-runtime.*.amazonaws.com or *.bedrock*.amazonaws.com
	if strings.Contains(host, "bedrock") && strings.HasSuffix(host, ".amazonaws.com") {
		if strings.HasPrefix(path, "/model/") && strings.Contains(path, "/invoke") {
			return "aws.bedrock", "chat", true
		}
	}

	// Google Gemini: generativelanguage.googleapis.com /v1*/models/*
	if host == "generativelanguage.googleapis.com" {
		if (strings.HasPrefix(path, "/v1/models/") || strings.HasPrefix(path, "/v1beta/models/")) {
			return "gcp.gemini", "chat", true
		}
	}

	// Fallback: any host with /v1/chat/completions → OpenAI-compatible
	if path == "/v1/chat/completions" {
		return "openai", "chat", true
	}

	return "", "", false
}

// extractHTTPHeader extracts a header value from raw HTTP data (case-insensitive).
func extractHTTPHeader(data []byte, name string) string {
	lower := bytes.ToLower(data)
	needle := []byte(strings.ToLower(name) + ": ")
	idx := bytes.Index(lower, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	end := bytes.Index(data[start:], []byte("\r\n"))
	if end < 0 {
		end = len(data) - start
	}
	return strings.TrimSpace(string(data[start : start+end]))
}

// parseHTTPLine extracts HTTP method, path, and host from request line + headers.
func parseHTTPLine(request []byte, attrs *SpanAttributes) {
	if len(request) == 0 {
		return
	}
	lineEnd := bytes.Index(request, []byte("\r\n"))
	if lineEnd < 0 {
		return
	}
	line := string(request[:lineEnd])
	parts := strings.SplitN(line, " ", 3)
	if len(parts) >= 2 {
		attrs.HTTPMethod = parts[0]
		attrs.HTTPPath = parts[1]
	}
	if attrs.HTTPHost == "" {
		attrs.HTTPHost = extractHTTPHeader(request, "Host")
	}
}

// parseHTTPResponseStatus extracts status code from HTTP response.
func parseHTTPResponseStatus(response []byte, attrs *SpanAttributes) {
	if len(response) == 0 {
		return
	}
	lineEnd := bytes.Index(response, []byte("\r\n"))
	if lineEnd < 0 {
		return
	}
	line := string(response[:lineEnd])
	// "HTTP/1.1 200 OK"
	parts := strings.SplitN(line, " ", 3)
	if len(parts) >= 2 {
		code, _ := strconv.Atoi(parts[1])
		attrs.HTTPStatusCode = code
	}

	// Check for SSE streaming
	ct := extractHTTPHeader(response, "Content-Type")
	if strings.Contains(ct, "text/event-stream") {
		attrs.GenAIStreaming = true
	}
}

// parseGenAIRequest extracts model and parameters from the JSON request body.
// Uses byte-level pattern matching for truncation tolerance (eBPF MAX_CAPTURE=256).
func parseGenAIRequest(request []byte, attrs *SpanAttributes) {
	body := extractHTTPBody(request)
	if len(body) == 0 {
		return
	}

	// Extract model
	if v := extractJSONString(body, "model"); v != "" {
		attrs.GenAIRequestModel = v
	}

	// Extract temperature
	if v := extractJSONNumber(body, "temperature"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			attrs.GenAITemperature = f
			attrs.GenAITemperatureSet = true
		}
	}

	// Extract top_p
	if v := extractJSONNumber(body, "top_p"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			attrs.GenAITopP = f
			attrs.GenAITopPSet = true
		}
	}

	// Extract max_tokens / max_completion_tokens
	for _, key := range []string{"max_tokens", "max_completion_tokens"} {
		if v := extractJSONNumber(body, key); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				attrs.GenAIMaxTokens = n
				attrs.GenAIMaxTokensSet = true
				break
			}
		}
	}

	// Detect streaming from request
	if v := extractJSONBool(body, "stream"); v == "true" {
		attrs.GenAIStreaming = true
	}
}

// parseGenAIResponse extracts model, tokens, and finish reason from the JSON response body.
func parseGenAIResponse(response []byte, attrs *SpanAttributes) {
	body := extractHTTPBody(response)
	if len(body) == 0 {
		return
	}

	// Response ID
	if v := extractJSONString(body, "id"); v != "" {
		attrs.GenAIResponseID = v
	}

	// Response model (may differ from request model)
	if v := extractJSONString(body, "model"); v != "" {
		attrs.GenAIResponseModel = v
	}

	// Finish reason: OpenAI uses "finish_reason", Anthropic uses "stop_reason"
	for _, key := range []string{"finish_reason", "stop_reason"} {
		if v := extractJSONString(body, key); v != "" {
			attrs.GenAIFinishReason = v
			break
		}
	}

	// Token usage - OpenAI format
	if v := extractJSONNumber(body, "prompt_tokens"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			attrs.GenAIInputTokens = n
			attrs.GenAIInputTokensSet = true
		}
	}
	if v := extractJSONNumber(body, "completion_tokens"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			attrs.GenAIOutputTokens = n
			attrs.GenAIOutputTokensSet = true
		}
	}

	// Anthropic format: "input_tokens", "output_tokens"
	if !attrs.GenAIInputTokensSet {
		if v := extractJSONNumber(body, "input_tokens"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				attrs.GenAIInputTokens = n
				attrs.GenAIInputTokensSet = true
			}
		}
	}
	if !attrs.GenAIOutputTokensSet {
		if v := extractJSONNumber(body, "output_tokens"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				attrs.GenAIOutputTokens = n
				attrs.GenAIOutputTokensSet = true
			}
		}
	}
}

// extractHTTPBody returns the body portion of an HTTP message (after \r\n\r\n).
// Handles eBPF-truncated headers: when \r\n\r\n is not found (headers exceed
// MAX_CAPTURE=256 bytes), falls back to finding JSON object start.
// Also handles chunked transfer encoding (skips chunk size lines).
func extractHTTPBody(data []byte) []byte {
	idx := bytes.Index(data, []byte("\r\n\r\n"))
	if idx >= 0 {
		body := data[idx+4:]
		// Handle chunked transfer: skip "hex-size\r\n" prefix
		if len(body) > 0 && ((body[0] >= '0' && body[0] <= '9') || (body[0] >= 'a' && body[0] <= 'f')) {
			if nl := bytes.Index(body, []byte("\r\n")); nl > 0 && nl < 8 {
				body = body[nl+2:]
			}
		}
		// If body has content, return it. If empty (e.g., \r\n\r\n was the
		// chunked encoding terminator "0\r\n\r\n" at the end), fall through
		// to the JSON-start fallback below.
		if len(body) > 0 {
			return body
		}
	}

	// Fallback for truncated headers: eBPF captures headers and body in
	// separate events. The concatenated buffer has truncated headers followed
	// directly by JSON body without \r\n\r\n. Find the first JSON object.
	// Look for '{"' which reliably indicates JSON object start (not in headers).
	jsonStart := bytes.Index(data, []byte(`{"`))
	if jsonStart > 0 {
		return data[jsonStart:]
	}
	// Also try pretty-printed JSON: "\r\n{\n" or "\r\n{\r\n" pattern
	chunkPattern := bytes.Index(data, []byte("\r\n{"))
	if chunkPattern >= 0 {
		return data[chunkPattern+2:]
	}
	return nil
}

// extractJSONString extracts a string value for a given key from JSON bytes.
// Handles truncated JSON gracefully (no full parse required).
// Looks for pattern: "key":"value" or "key": "value"
func extractJSONString(data []byte, key string) string {
	needle := []byte(`"` + key + `"`)
	idx := bytes.Index(data, needle)
	if idx < 0 {
		return ""
	}

	// Skip past key and find colon
	rest := data[idx+len(needle):]
	rest = bytes.TrimLeft(rest, " \t\n\r")
	if len(rest) == 0 || rest[0] != ':' {
		return ""
	}
	rest = rest[1:]
	rest = bytes.TrimLeft(rest, " \t\n\r")

	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]

	// Find closing quote (handle escaped quotes)
	var result []byte
	for i := 0; i < len(rest); i++ {
		if rest[i] == '\\' && i+1 < len(rest) {
			result = append(result, rest[i+1])
			i++
			continue
		}
		if rest[i] == '"' {
			return string(result)
		}
		result = append(result, rest[i])
	}

	// Truncated — return what we have if it looks reasonable
	if len(result) > 0 {
		return string(result)
	}
	return ""
}

// extractJSONNumber extracts a numeric value for a given key from JSON bytes.
// Looks for pattern: "key":123 or "key": 123.45
func extractJSONNumber(data []byte, key string) string {
	needle := []byte(`"` + key + `"`)
	idx := bytes.Index(data, needle)
	if idx < 0 {
		return ""
	}

	rest := data[idx+len(needle):]
	rest = bytes.TrimLeft(rest, " \t\n\r")
	if len(rest) == 0 || rest[0] != ':' {
		return ""
	}
	rest = rest[1:]
	rest = bytes.TrimLeft(rest, " \t\n\r")

	// Collect digits, dots, minus
	var num []byte
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if (c >= '0' && c <= '9') || c == '.' || c == '-' || c == 'e' || c == 'E' || c == '+' {
			num = append(num, c)
		} else {
			break
		}
	}

	if len(num) == 0 {
		return ""
	}
	return string(num)
}

// extractJSONBool extracts a boolean value for a given key from JSON bytes.
// Returns "true" or "false" or "" if not found.
func extractJSONBool(data []byte, key string) string {
	needle := []byte(`"` + key + `"`)
	idx := bytes.Index(data, needle)
	if idx < 0 {
		return ""
	}

	rest := data[idx+len(needle):]
	rest = bytes.TrimLeft(rest, " \t\n\r")
	if len(rest) == 0 || rest[0] != ':' {
		return ""
	}
	rest = rest[1:]
	rest = bytes.TrimLeft(rest, " \t\n\r")

	if bytes.HasPrefix(rest, []byte("true")) {
		return "true"
	}
	if bytes.HasPrefix(rest, []byte("false")) {
		return "false"
	}
	return ""
}

// Refine promotes a detected protocol to a more specific one when additional
// context is available. Currently promotes "http" -> "genai" when GenAI
// endpoints are detected.
func Refine(proto string, request []byte, port uint16) string {
	if proto != ProtoHTTP {
		return proto
	}
	if _, _, ok := detectGenAI(request); ok {
		return ProtoGenAI
	}
	return proto
}
