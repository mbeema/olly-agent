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
	ProtoUnknown  = "unknown"
)

// SpanAttributes holds parsed protocol attributes for span generation.
type SpanAttributes struct {
	Protocol string
	Name     string // span name (e.g., "GET /api/users", "SELECT", "GET key")

	// HTTP
	HTTPMethod     string
	HTTPPath       string
	HTTPStatusCode int
	HTTPHost       string
	HTTPUserAgent  string
	ContentLength  int64

	// Database
	DBSystem    string
	DBStatement string
	DBOperation string
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

	// General
	Error      bool
	ErrorMsg   string
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

// Parse uses the appropriate parser to extract span attributes.
func Parse(proto string, request, response []byte) (*SpanAttributes, error) {
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
