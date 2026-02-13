// MCP Demo Server — Streamable HTTP transport (MCP spec 2025-03-26)
//
// Implements a lightweight MCP server with:
//   - tools/list, tools/call (get_weather, lookup_user, calculate)
//   - resources/list, resources/read (config://app, db://users/count)
//   - prompts/list, prompts/get (code_review, summarize)
//   - initialize, ping
//
// All responses are JSON-RPC 2.0 over HTTP POST on /mcp (port 3002).
// Olly's eBPF hooks capture this traffic and produce mcp.* spans with zero instrumentation.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strings"
	"time"
)

// JSON-RPC 2.0 types

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP types

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
}

type mcpResource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MimeType    string `json:"mimeType,omitempty"`
}

type mcpPrompt struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Arguments   json.RawMessage `json:"arguments,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Server state
var sessionCounter int

func main() {
	http.HandleFunc("/mcp", mcpHandler)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "service": "mcp-server"})
	})

	port := getenv("PORT", "3002")
	log.Printf("mcp-server listening on :%s (Streamable HTTP)", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mcpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, nil, -32700, "Parse error")
		return
	}

	if req.JSONRPC != "2.0" {
		writeError(w, req.ID, -32600, "Invalid Request: jsonrpc must be 2.0")
		return
	}

	log.Printf("MCP request: method=%s id=%s", req.Method, string(req.ID))

	switch req.Method {
	case "initialize":
		handleInitialize(w, req)
	case "ping":
		handlePing(w, req)
	case "notifications/initialized":
		// Notification — no response needed, but we send 202 per spec
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		handleToolsList(w, req)
	case "tools/call":
		handleToolsCall(w, req)
	case "resources/list":
		handleResourcesList(w, req)
	case "resources/read":
		handleResourcesRead(w, req)
	case "prompts/list":
		handlePromptsList(w, req)
	case "prompts/get":
		handlePromptsGet(w, req)
	default:
		writeError(w, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func handleInitialize(w http.ResponseWriter, req jsonRPCRequest) {
	sessionCounter++
	sessionID := fmt.Sprintf("sess-%d-%d", time.Now().Unix(), sessionCounter)

	w.Header().Set("Mcp-Session-Id", sessionID)
	writeResult(w, req.ID, map[string]interface{}{
		"protocolVersion": "2025-03-26",
		"capabilities": map[string]interface{}{
			"tools":     map[string]interface{}{},
			"resources": map[string]interface{}{"subscribe": true},
			"prompts":   map[string]interface{}{},
		},
		"serverInfo": map[string]interface{}{
			"name":    "olly-mcp-demo",
			"version": "1.0.0",
		},
	})
}

func handlePing(w http.ResponseWriter, req jsonRPCRequest) {
	writeResult(w, req.ID, map[string]interface{}{})
}

func handleToolsList(w http.ResponseWriter, req jsonRPCRequest) {
	tools := []mcpTool{
		{
			Name:        "get_weather",
			Description: "Get current weather for a location",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"location":{"type":"string","description":"City name"}},"required":["location"]}`),
		},
		{
			Name:        "lookup_user",
			Description: "Look up a user by ID",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"user_id":{"type":"integer","description":"User ID"}},"required":["user_id"]}`),
		},
		{
			Name:        "calculate",
			Description: "Evaluate a mathematical expression",
			InputSchema: json.RawMessage(`{"type":"object","properties":{"expression":{"type":"string","description":"Math expression (e.g., 2+2, sqrt(16))"}},"required":["expression"]}`),
		},
	}
	writeResult(w, req.ID, map[string]interface{}{"tools": tools})
}

func handleToolsCall(w http.ResponseWriter, req jsonRPCRequest) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, -32602, "Invalid params")
		return
	}

	log.Printf("tools/call: name=%s", params.Name)

	switch params.Name {
	case "get_weather":
		var args struct {
			Location string `json:"location"`
		}
		json.Unmarshal(params.Arguments, &args)
		if args.Location == "" {
			args.Location = "unknown"
		}
		// Simulate weather lookup with some latency
		time.Sleep(50 * time.Millisecond)
		text := fmt.Sprintf("Weather in %s: 72°F, sunny with light breeze. Humidity: 45%%.", args.Location)
		writeResult(w, req.ID, map[string]interface{}{
			"content": []mcpContent{{Type: "text", Text: text}},
		})

	case "lookup_user":
		var args struct {
			UserID int `json:"user_id"`
		}
		json.Unmarshal(params.Arguments, &args)
		time.Sleep(30 * time.Millisecond)
		text := fmt.Sprintf(`{"id":%d,"name":"User-%d","email":"user%d@demo.com","role":"member"}`, args.UserID, args.UserID, args.UserID)
		writeResult(w, req.ID, map[string]interface{}{
			"content": []mcpContent{{Type: "text", Text: text}},
		})

	case "calculate":
		var args struct {
			Expression string `json:"expression"`
		}
		json.Unmarshal(params.Arguments, &args)
		result := evaluateSimple(args.Expression)
		writeResult(w, req.ID, map[string]interface{}{
			"content": []mcpContent{{Type: "text", Text: result}},
		})

	default:
		writeError(w, req.ID, -32602, fmt.Sprintf("Unknown tool: %s", params.Name))
	}
}

func handleResourcesList(w http.ResponseWriter, req jsonRPCRequest) {
	resources := []mcpResource{
		{URI: "config://app", Name: "App Configuration", Description: "Current application config", MimeType: "application/json"},
		{URI: "db://users/count", Name: "User Count", Description: "Total number of registered users", MimeType: "text/plain"},
		{URI: "file:///var/log/demo-app/app.log", Name: "App Log", Description: "Recent application log entries", MimeType: "text/plain"},
	}
	writeResult(w, req.ID, map[string]interface{}{"resources": resources})
}

func handleResourcesRead(w http.ResponseWriter, req jsonRPCRequest) {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, -32602, "Invalid params")
		return
	}

	log.Printf("resources/read: uri=%s", params.URI)
	time.Sleep(20 * time.Millisecond)

	switch params.URI {
	case "config://app":
		writeResult(w, req.ID, map[string]interface{}{
			"contents": []map[string]interface{}{
				{"uri": params.URI, "mimeType": "application/json", "text": `{"port":5000,"debug":false,"db_host":"localhost","workers":4}`},
			},
		})
	case "db://users/count":
		writeResult(w, req.ID, map[string]interface{}{
			"contents": []map[string]interface{}{
				{"uri": params.URI, "mimeType": "text/plain", "text": "42"},
			},
		})
	default:
		writeError(w, req.ID, -32602, fmt.Sprintf("Resource not found: %s", params.URI))
	}
}

func handlePromptsList(w http.ResponseWriter, req jsonRPCRequest) {
	prompts := []mcpPrompt{
		{
			Name:        "code_review",
			Description: "Review code for bugs and improvements",
			Arguments:   json.RawMessage(`[{"name":"language","description":"Programming language","required":true}]`),
		},
		{
			Name:        "summarize",
			Description: "Summarize text content",
			Arguments:   json.RawMessage(`[{"name":"style","description":"Summary style: brief, detailed","required":false}]`),
		},
	}
	writeResult(w, req.ID, map[string]interface{}{"prompts": prompts})
}

func handlePromptsGet(w http.ResponseWriter, req jsonRPCRequest) {
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeError(w, req.ID, -32602, "Invalid params")
		return
	}

	log.Printf("prompts/get: name=%s", params.Name)

	switch params.Name {
	case "code_review":
		lang := params.Arguments["language"]
		if lang == "" {
			lang = "go"
		}
		writeResult(w, req.ID, map[string]interface{}{
			"description": "Code review prompt",
			"messages": []map[string]interface{}{
				{"role": "user", "content": map[string]string{
					"type": "text",
					"text": fmt.Sprintf("Please review the following %s code for bugs, security issues, and improvements. Focus on correctness first, then performance.", lang),
				}},
			},
		})
	case "summarize":
		style := params.Arguments["style"]
		if style == "" {
			style = "brief"
		}
		writeResult(w, req.ID, map[string]interface{}{
			"description": "Summarization prompt",
			"messages": []map[string]interface{}{
				{"role": "user", "content": map[string]string{
					"type": "text",
					"text": fmt.Sprintf("Summarize the following content in a %s style. Highlight key points.", style),
				}},
			},
		})
	default:
		writeError(w, req.ID, -32602, fmt.Sprintf("Unknown prompt: %s", params.Name))
	}
}

// JSON-RPC helpers

func writeResult(w http.ResponseWriter, id json.RawMessage, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: message},
	})
}

// Simple math evaluator
func evaluateSimple(expr string) string {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "sqrt(") && strings.HasSuffix(expr, ")") {
		inner := expr[5 : len(expr)-1]
		var n float64
		if _, err := fmt.Sscanf(inner, "%f", &n); err == nil {
			return fmt.Sprintf("%.4f", math.Sqrt(n))
		}
	}
	// Try simple a+b, a*b, a-b, a/b
	for _, op := range []string{"+", "-", "*", "/"} {
		if parts := strings.SplitN(expr, op, 2); len(parts) == 2 {
			var a, b float64
			if _, err := fmt.Sscanf(strings.TrimSpace(parts[0]), "%f", &a); err != nil {
				continue
			}
			if _, err := fmt.Sscanf(strings.TrimSpace(parts[1]), "%f", &b); err != nil {
				continue
			}
			switch op {
			case "+":
				return fmt.Sprintf("%.4f", a+b)
			case "-":
				return fmt.Sprintf("%.4f", a-b)
			case "*":
				return fmt.Sprintf("%.4f", a*b)
			case "/":
				if b == 0 {
					return "Error: division by zero"
				}
				return fmt.Sprintf("%.4f", a/b)
			}
		}
	}
	return fmt.Sprintf("Cannot evaluate: %s", expr)
}
