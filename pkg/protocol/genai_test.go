// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package protocol

import (
	"strings"
	"testing"
)

func TestGenAIDetect(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		expect bool
	}{
		{
			name:   "OpenAI chat completions",
			data:   "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
			expect: true,
		},
		{
			name:   "OpenAI embeddings",
			data:   "POST /v1/embeddings HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
			expect: true,
		},
		{
			name:   "OpenAI completions",
			data:   "POST /v1/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
			expect: true,
		},
		{
			name:   "Anthropic messages",
			data:   "POST /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n",
			expect: true,
		},
		{
			name:   "AWS Bedrock invoke",
			data:   "POST /model/anthropic.claude-3-sonnet/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-east-1.amazonaws.com\r\n\r\n",
			expect: true,
		},
		{
			name:   "Google Gemini",
			data:   "POST /v1beta/models/gemini-pro:generateContent HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\n\r\n",
			expect: true,
		},
		{
			name:   "Cohere v2 chat",
			data:   "POST /v2/chat HTTP/1.1\r\nHost: api.cohere.ai\r\n\r\n",
			expect: true,
		},
		{
			name:   "Mistral chat",
			data:   "POST /v1/chat/completions HTTP/1.1\r\nHost: api.mistral.ai\r\n\r\n",
			expect: true,
		},
		{
			name:   "Ollama chat",
			data:   "POST /api/chat HTTP/1.1\r\nHost: localhost:11434\r\n\r\n",
			expect: true,
		},
		{
			name:   "OpenAI compatible - any host",
			data:   "POST /v1/chat/completions HTTP/1.1\r\nHost: my-llm-proxy.internal:8080\r\n\r\n",
			expect: true,
		},
		{
			name:   "Regular HTTP GET - not GenAI",
			data:   "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expect: false,
		},
		{
			name:   "Regular POST - not GenAI",
			data:   "POST /api/orders HTTP/1.1\r\nHost: example.com\r\n\r\n",
			expect: false,
		},
		{
			name:   "GET to OpenAI - not GenAI (must be POST)",
			data:   "GET /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n",
			expect: false,
		},
		{
			name:   "Too short",
			data:   "POST",
			expect: false,
		},
	}

	parser := &GenAIParser{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parser.Detect([]byte(tt.data), 443)
			if got != tt.expect {
				t.Errorf("Detect() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestGenAIParseOpenAI(t *testing.T) {
	request := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}],"temperature":0.7,"max_tokens":100}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"id":"chatcmpl-abc123","object":"chat.completion","model":"gpt-4o-2024-08-06","choices":[{"index":0,"message":{"role":"assistant","content":"Hi!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":25,"completion_tokens":10,"total_tokens":35}}`

	parser := &GenAIParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.Protocol != ProtoGenAI {
		t.Errorf("Protocol = %q, want %q", attrs.Protocol, ProtoGenAI)
	}
	if attrs.GenAIProvider != "openai" {
		t.Errorf("Provider = %q, want %q", attrs.GenAIProvider, "openai")
	}
	if attrs.GenAIOperation != "chat" {
		t.Errorf("Operation = %q, want %q", attrs.GenAIOperation, "chat")
	}
	if attrs.GenAIRequestModel != "gpt-4o" {
		t.Errorf("RequestModel = %q, want %q", attrs.GenAIRequestModel, "gpt-4o")
	}
	if attrs.GenAIResponseModel != "gpt-4o-2024-08-06" {
		t.Errorf("ResponseModel = %q, want %q", attrs.GenAIResponseModel, "gpt-4o-2024-08-06")
	}
	if attrs.GenAIResponseID != "chatcmpl-abc123" {
		t.Errorf("ResponseID = %q, want %q", attrs.GenAIResponseID, "chatcmpl-abc123")
	}
	if attrs.GenAIFinishReason != "stop" {
		t.Errorf("FinishReason = %q, want %q", attrs.GenAIFinishReason, "stop")
	}
	if !attrs.GenAIInputTokensSet || attrs.GenAIInputTokens != 25 {
		t.Errorf("InputTokens = %d (set=%v), want 25", attrs.GenAIInputTokens, attrs.GenAIInputTokensSet)
	}
	if !attrs.GenAIOutputTokensSet || attrs.GenAIOutputTokens != 10 {
		t.Errorf("OutputTokens = %d (set=%v), want 10", attrs.GenAIOutputTokens, attrs.GenAIOutputTokensSet)
	}
	if !attrs.GenAITemperatureSet || attrs.GenAITemperature != 0.7 {
		t.Errorf("Temperature = %f (set=%v), want 0.7", attrs.GenAITemperature, attrs.GenAITemperatureSet)
	}
	if !attrs.GenAIMaxTokensSet || attrs.GenAIMaxTokens != 100 {
		t.Errorf("MaxTokens = %d (set=%v), want 100", attrs.GenAIMaxTokens, attrs.GenAIMaxTokensSet)
	}
	if attrs.Name != "chat gpt-4o-2024-08-06" {
		t.Errorf("Name = %q, want %q", attrs.Name, "chat gpt-4o-2024-08-06")
	}
	if attrs.HTTPMethod != "POST" {
		t.Errorf("HTTPMethod = %q, want POST", attrs.HTTPMethod)
	}
	if attrs.HTTPStatusCode != 200 {
		t.Errorf("HTTPStatusCode = %d, want 200", attrs.HTTPStatusCode)
	}
}

func TestGenAIParseAnthropic(t *testing.T) {
	request := "POST /v1/messages HTTP/1.1\r\n" +
		"Host: api.anthropic.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"model":"claude-3-5-sonnet-20241022","messages":[{"role":"user","content":"Hello"}],"max_tokens":256}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"id":"msg_01XYZ","type":"message","model":"claude-3-5-sonnet-20241022","stop_reason":"end_turn","usage":{"input_tokens":12,"output_tokens":8}}`

	parser := &GenAIParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.GenAIProvider != "anthropic" {
		t.Errorf("Provider = %q, want %q", attrs.GenAIProvider, "anthropic")
	}
	if attrs.GenAIRequestModel != "claude-3-5-sonnet-20241022" {
		t.Errorf("RequestModel = %q, want %q", attrs.GenAIRequestModel, "claude-3-5-sonnet-20241022")
	}
	if attrs.GenAIFinishReason != "end_turn" {
		t.Errorf("FinishReason = %q, want %q", attrs.GenAIFinishReason, "end_turn")
	}
	if !attrs.GenAIInputTokensSet || attrs.GenAIInputTokens != 12 {
		t.Errorf("InputTokens = %d, want 12", attrs.GenAIInputTokens)
	}
	if !attrs.GenAIOutputTokensSet || attrs.GenAIOutputTokens != 8 {
		t.Errorf("OutputTokens = %d, want 8", attrs.GenAIOutputTokens)
	}
	if attrs.Name != "chat claude-3-5-sonnet-20241022" {
		t.Errorf("Name = %q, want %q", attrs.Name, "chat claude-3-5-sonnet-20241022")
	}
}

func TestGenAIParseEmbeddings(t *testing.T) {
	request := "POST /v1/embeddings HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"model":"text-embedding-3-small","input":"Hello world"}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"object":"list","data":[{"object":"embedding","index":0}],"model":"text-embedding-3-small","usage":{"prompt_tokens":3,"total_tokens":3}}`

	parser := &GenAIParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.GenAIOperation != "embeddings" {
		t.Errorf("Operation = %q, want %q", attrs.GenAIOperation, "embeddings")
	}
	if attrs.Name != "embeddings text-embedding-3-small" {
		t.Errorf("Name = %q, want %q", attrs.Name, "embeddings text-embedding-3-small")
	}
	if !attrs.GenAIInputTokensSet || attrs.GenAIInputTokens != 3 {
		t.Errorf("InputTokens = %d, want 3", attrs.GenAIInputTokens)
	}
}

func TestGenAIParseTruncated(t *testing.T) {
	// Simulate eBPF MAX_CAPTURE=256 truncation
	fullRequest := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"model":"gpt-4o","messages":[{"role":"user","content":"Tell me a very long story about..."}],"temperature":0.7,"max_tokens":4096}`

	// Truncate to 256 bytes
	truncated := fullRequest
	if len(truncated) > 256 {
		truncated = truncated[:256]
	}

	parser := &GenAIParser{}
	attrs, err := parser.Parse([]byte(truncated), nil)
	if err != nil {
		t.Fatal(err)
	}

	// Model should still be extracted from truncated data
	if attrs.GenAIRequestModel != "gpt-4o" {
		t.Errorf("RequestModel = %q, want %q (from truncated data)", attrs.GenAIRequestModel, "gpt-4o")
	}
	if attrs.GenAIProvider != "openai" {
		t.Errorf("Provider = %q, want %q", attrs.GenAIProvider, "openai")
	}
	// Tokens won't be available (no response)
	if attrs.GenAIInputTokensSet {
		t.Error("InputTokensSet should be false with no response")
	}
}

func TestGenAIParseSSE(t *testing.T) {
	request := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}],"stream":true}`

	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/event-stream\r\n" +
		"\r\n" +
		`data: {"id":"chatcmpl-abc","object":"chat.completion.chunk","model":"gpt-4o","choices":[{"delta":{"content":"Hi"}}]}`

	parser := &GenAIParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if !attrs.GenAIStreaming {
		t.Error("GenAIStreaming should be true for SSE response")
	}
	if attrs.GenAIResponseModel != "gpt-4o" {
		t.Errorf("ResponseModel = %q, want %q", attrs.GenAIResponseModel, "gpt-4o")
	}
}

func TestGenAIParseError429(t *testing.T) {
	request := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`

	response := "HTTP/1.1 429 Too Many Requests\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"error":{"message":"Rate limit exceeded","type":"rate_limit_error"}}`

	parser := &GenAIParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	if attrs.HTTPStatusCode != 429 {
		t.Errorf("HTTPStatusCode = %d, want 429", attrs.HTTPStatusCode)
	}
	if !attrs.Error {
		t.Error("Error should be true for 429")
	}
}

func TestGenAIParseError500(t *testing.T) {
	request := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`

	response := "HTTP/1.1 500 Internal Server Error\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"error":{"message":"Internal server error"}}`

	parser := &GenAIParser{}
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

func TestGenAIParseEmptyBody(t *testing.T) {
	request := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"\r\n"

	parser := &GenAIParser{}
	attrs, err := parser.Parse([]byte(request), nil)
	if err != nil {
		t.Fatal(err)
	}

	if attrs.GenAIProvider != "openai" {
		t.Errorf("Provider = %q, want %q", attrs.GenAIProvider, "openai")
	}
	if attrs.GenAIRequestModel != "" {
		t.Errorf("RequestModel = %q, want empty", attrs.GenAIRequestModel)
	}
	if attrs.Name != "chat" {
		t.Errorf("Name = %q, want %q", attrs.Name, "chat")
	}
}

func TestGenAIRefine(t *testing.T) {
	genaiRequest := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n"
	regularRequest := "GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n"

	// HTTP + GenAI endpoint → genai
	if got := Refine("http", []byte(genaiRequest), 443); got != "genai" {
		t.Errorf("Refine(http, genai) = %q, want %q", got, "genai")
	}

	// HTTP + regular endpoint → stays http
	if got := Refine("http", []byte(regularRequest), 80); got != "http" {
		t.Errorf("Refine(http, regular) = %q, want %q", got, "http")
	}

	// Non-HTTP → unchanged
	if got := Refine("postgres", []byte(genaiRequest), 5432); got != "postgres" {
		t.Errorf("Refine(postgres, ...) = %q, want %q", got, "postgres")
	}
}

func TestExtractJSONString(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		key    string
		expect string
	}{
		{
			name:   "simple string",
			data:   `{"model":"gpt-4o","temperature":0.7}`,
			key:    "model",
			expect: "gpt-4o",
		},
		{
			name:   "with spaces",
			data:   `{"model" : "gpt-4o"}`,
			key:    "model",
			expect: "gpt-4o",
		},
		{
			name:   "escaped quote",
			data:   `{"content":"say \"hello\""}`,
			key:    "content",
			expect: `say "hello"`,
		},
		{
			name:   "truncated value",
			data:   `{"model":"gpt-4o-2024`,
			key:    "model",
			expect: "gpt-4o-2024",
		},
		{
			name:   "missing key",
			data:   `{"other":"value"}`,
			key:    "model",
			expect: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJSONString([]byte(tt.data), tt.key)
			if got != tt.expect {
				t.Errorf("extractJSONString(%q) = %q, want %q", tt.key, got, tt.expect)
			}
		})
	}
}

func TestExtractJSONNumber(t *testing.T) {
	tests := []struct {
		data   string
		key    string
		expect string
	}{
		{`{"prompt_tokens":25}`, "prompt_tokens", "25"},
		{`{"temperature": 0.7}`, "temperature", "0.7"},
		{`{"max_tokens":4096,"model":"gpt-4o"}`, "max_tokens", "4096"},
		{`{"other":123}`, "missing", ""},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := extractJSONNumber([]byte(tt.data), tt.key)
			if got != tt.expect {
				t.Errorf("extractJSONNumber(%q) = %q, want %q", tt.key, got, tt.expect)
			}
		})
	}
}

func TestExtractJSONBool(t *testing.T) {
	tests := []struct {
		data   string
		key    string
		expect string
	}{
		{`{"stream":true}`, "stream", "true"},
		{`{"stream":false}`, "stream", "false"},
		{`{"stream": true}`, "stream", "true"},
		{`{"other":true}`, "stream", ""},
	}

	for _, tt := range tests {
		t.Run(tt.expect, func(t *testing.T) {
			got := extractJSONBool([]byte(tt.data), tt.key)
			if got != tt.expect {
				t.Errorf("extractJSONBool(%q) = %q, want %q", tt.key, got, tt.expect)
			}
		})
	}
}

func TestDetectGenAIBedrock(t *testing.T) {
	data := "POST /model/anthropic.claude-v2/invoke HTTP/1.1\r\nHost: bedrock-runtime.us-west-2.amazonaws.com\r\n\r\n"
	provider, op, ok := detectGenAI([]byte(data))
	if !ok {
		t.Fatal("expected detection")
	}
	if provider != "aws.bedrock" {
		t.Errorf("provider = %q, want aws.bedrock", provider)
	}
	if op != "chat" {
		t.Errorf("operation = %q, want chat", op)
	}
}

func TestDetectGenAIGemini(t *testing.T) {
	data := "POST /v1/models/gemini-pro:generateContent HTTP/1.1\r\nHost: generativelanguage.googleapis.com\r\n\r\n"
	provider, op, ok := detectGenAI([]byte(data))
	if !ok {
		t.Fatal("expected detection")
	}
	if provider != "gcp.gemini" {
		t.Errorf("provider = %q, want gcp.gemini", provider)
	}
	if op != "chat" {
		t.Errorf("operation = %q, want chat", op)
	}
}

func TestGenAISpanNameNoModel(t *testing.T) {
	// When model can't be extracted (empty body), name is just the operation
	request := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n"
	parser := &GenAIParser{}
	attrs, _ := parser.Parse([]byte(request), nil)
	if attrs.Name != "chat" {
		t.Errorf("Name = %q, want %q", attrs.Name, "chat")
	}
}

func TestGenAIParseTopP(t *testing.T) {
	request := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"\r\n" +
		`{"model":"gpt-4o","top_p":0.9}`

	parser := &GenAIParser{}
	attrs, _ := parser.Parse([]byte(request), nil)

	if !attrs.GenAITopPSet || attrs.GenAITopP != 0.9 {
		t.Errorf("TopP = %f (set=%v), want 0.9", attrs.GenAITopP, attrs.GenAITopPSet)
	}
}

func TestGenAIMaxCompletionTokens(t *testing.T) {
	request := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"\r\n" +
		`{"model":"gpt-4o","max_completion_tokens":1024}`

	parser := &GenAIParser{}
	attrs, _ := parser.Parse([]byte(request), nil)

	if !attrs.GenAIMaxTokensSet || attrs.GenAIMaxTokens != 1024 {
		t.Errorf("MaxTokens = %d (set=%v), want 1024", attrs.GenAIMaxTokens, attrs.GenAIMaxTokensSet)
	}
}

func TestGenAIHostCaseInsensitive(t *testing.T) {
	// Host header extraction should work with different casings
	data := "POST /v1/chat/completions HTTP/1.1\r\nhost: api.openai.com\r\n\r\n"
	_, _, ok := detectGenAI([]byte(data))
	if !ok {
		t.Error("expected detection with lowercase host header")
	}
}

func TestGenAINoDoubleRegister(t *testing.T) {
	// Verify GenAI isn't in the main registry (it uses Refine instead)
	for _, p := range registry {
		if p.Name() == ProtoGenAI {
			t.Error("GenAIParser should NOT be in registry (uses Refine, not Detect)")
		}
	}
}

func TestRefinePreservesNonHTTP(t *testing.T) {
	protos := []string{"postgres", "mysql", "redis", "mongodb", "grpc", "dns", "unknown"}
	for _, p := range protos {
		if got := Refine(p, []byte("POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\n\r\n"), 0); got != p {
			t.Errorf("Refine(%q) = %q, want %q", p, got, p)
		}
	}
}

func TestExtractHTTPBody(t *testing.T) {
	data := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"hello\":\"world\"}"
	body := extractHTTPBody([]byte(data))
	if string(body) != `{"hello":"world"}` {
		t.Errorf("body = %q, want %q", string(body), `{"hello":"world"}`)
	}

	// No body separator
	noBody := "HTTP/1.1 200 OK"
	if got := extractHTTPBody([]byte(noBody)); got != nil {
		t.Errorf("expected nil body, got %q", string(got))
	}
}

func TestExtractHTTPHeader(t *testing.T) {
	data := "POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n"
	if got := extractHTTPHeader([]byte(data), "Host"); got != "api.openai.com" {
		t.Errorf("Host = %q, want api.openai.com", got)
	}
	if got := extractHTTPHeader([]byte(data), "Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := extractHTTPHeader([]byte(data), "Missing"); got != "" {
		t.Errorf("Missing = %q, want empty", got)
	}
}

func TestGenAILargeResponseTruncated(t *testing.T) {
	request := "POST /v1/chat/completions HTTP/1.1\r\n" +
		"Host: api.openai.com\r\n" +
		"\r\n" +
		`{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}`

	// Build a large response that gets truncated
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"\r\n" +
		`{"id":"chatcmpl-xyz","model":"gpt-4o","choices":[{"message":{"content":"` +
		strings.Repeat("A", 300) + // This will push usage beyond 256 bytes
		`"}}],"usage":{"prompt_tokens":10,"completion_tokens":50}}`

	// Truncate to 256 bytes (simulating eBPF capture limit)
	if len(response) > 256 {
		response = response[:256]
	}

	parser := &GenAIParser{}
	attrs, err := parser.Parse([]byte(request), []byte(response))
	if err != nil {
		t.Fatal(err)
	}

	// Model should be extractable from truncated response
	if attrs.GenAIResponseModel != "gpt-4o" {
		t.Errorf("ResponseModel = %q, want gpt-4o", attrs.GenAIResponseModel)
	}
	// Tokens are likely truncated away
	if attrs.GenAIInputTokensSet {
		t.Log("InputTokens unexpectedly available from truncated response (OK if body was short enough)")
	}
}

func TestExtractHTTPBodyPrettyJSON(t *testing.T) {
	// Pretty-printed JSON after truncated headers (OpenAI actual format).
	// The { is NOT immediately followed by " — there's whitespace.
	response := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSome-Long-Header: " +
		strings.Repeat("x", 200) + // push past 256 bytes
		"\r\n{\n  \"id\": \"test\",\n  \"model\": \"gpt-4o\"\n}\r\n0\r\n\r\n"

	body := extractHTTPBody([]byte(response))
	if body == nil || len(body) == 0 {
		t.Fatal("extractHTTPBody returned nil/empty for pretty-printed JSON")
	}
	if !strings.Contains(string(body), `"model"`) {
		t.Errorf("body missing model, got: %s", string(body))
	}
}

func TestExtractHTTPBodyEBPFChunked(t *testing.T) {
	// Simulates actual eBPF capture: two SSL_read events concatenated.
	// First event (256 bytes): truncated headers ending mid-value.
	// Second event: rest of chunked body with chunk terminator "0\r\n\r\n".
	// The \r\n\r\n at position 513 is the chunk terminator, NOT header/body separator.
	response := "HTTP/1.1 200 OK\r\n" +
		"Date: Fri, 13 Feb 2026 01:19:44 GMT\r\n" +
		"Content-Type: application/json\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Connection: close\r\n" +
		"access-control-expose-headers: X-Request-ID\r\n" +
		"openai-organization: user-mhqkyfhslyg7jkobppfh5gaj\r\n" +
		"openai-processing-ms: 421" +
		// eBPF truncation at 256 bytes — first event ends here
		// Second SSL_read event starts with the chunk body:
		"\r\n" + // end of last truncated header
		`{"id":"chatcmpl-test","model":"gpt-4o-mini-2024-07-18","choices":[{"index":0}]}` +
		"\r\n0\r\n\r\n" // chunk terminator

	body := extractHTTPBody([]byte(response))
	if body == nil {
		t.Fatal("extractHTTPBody returned nil")
	}
	// Should find JSON body, not empty string from chunk terminator's \r\n\r\n
	if len(body) == 0 {
		t.Fatal("extractHTTPBody returned empty body (matched chunk terminator instead of body)")
	}
	if !strings.Contains(string(body), `"model":"gpt-4o-mini-2024-07-18"`) {
		t.Errorf("body missing model field, got: %s", string(body))
	}
}
