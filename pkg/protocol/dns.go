package protocol

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DNS record types
const (
	dnsTypeA     = 1
	dnsTypeNS    = 2
	dnsTypeCNAME = 5
	dnsTypeSOA   = 6
	dnsTypeMX    = 15
	dnsTypeTXT   = 16
	dnsTypeAAAA  = 28
	dnsTypeSRV   = 33
)

// DNS response codes
const (
	dnsRcodeNoError  = 0
	dnsRcodeFormErr  = 1
	dnsRcodeServFail = 2
	dnsRcodeNXDomain = 3
	dnsRcodeNotImpl  = 4
	dnsRcodeRefused  = 5
)

// DNSParser parses DNS protocol.
type DNSParser struct{}

func (p *DNSParser) Name() string { return ProtoDNS }

func (p *DNSParser) Detect(data []byte, port uint16) bool {
	if len(data) < 12 {
		return false
	}

	// DNS header: ID(2) + Flags(2) + QDCount(2) + ANCount(2) + NSCount(2) + ARCount(2)
	flags := binary.BigEndian.Uint16(data[2:4])
	qdCount := binary.BigEndian.Uint16(data[4:6])
	anCount := binary.BigEndian.Uint16(data[6:8])

	// QR bit (bit 15): 0=query, 1=response
	isResponse := (flags & 0x8000) != 0

	// Opcode (bits 11-14): 0=standard query
	opcode := (flags >> 11) & 0x0F

	// Sanity checks
	if opcode > 2 {
		return false
	}

	if !isResponse && qdCount >= 1 && qdCount <= 10 {
		return true
	}

	if isResponse && (qdCount >= 1 || anCount >= 1) {
		return true
	}

	return port == 53
}

func (p *DNSParser) Parse(request, response []byte) (*SpanAttributes, error) {
	attrs := &SpanAttributes{
		Protocol: ProtoDNS,
	}

	// Parse query
	if len(request) >= 12 {
		qdCount := binary.BigEndian.Uint16(request[4:6])

		if qdCount > 0 {
			name, qtype := parseDNSQuestion(request[12:])
			attrs.DNSName = name
			attrs.DNSType = dnsTypeName(qtype)
		}
	}

	// Parse response
	if len(response) >= 12 {
		flags := binary.BigEndian.Uint16(response[2:4])
		rcode := flags & 0x000F
		anCount := binary.BigEndian.Uint16(response[6:8])

		attrs.DNSRcode = dnsRcodeName(int(rcode))
		attrs.DNSAnswers = int(anCount)

		if rcode != dnsRcodeNoError {
			attrs.Error = true
			attrs.ErrorMsg = fmt.Sprintf("DNS %s", attrs.DNSRcode)
		}
	}

	// Build span name
	if attrs.DNSName != "" {
		attrs.Name = fmt.Sprintf("DNS %s %s", attrs.DNSType, attrs.DNSName)
	} else {
		attrs.Name = "DNS"
	}

	return attrs, nil
}

// parseDNSQuestion parses the first question from DNS wire format.
func parseDNSQuestion(data []byte) (name string, qtype uint16) {
	var parts []string
	offset := 0

	for offset < len(data) {
		labelLen := int(data[offset])
		if labelLen == 0 {
			offset++
			break
		}

		// Pointer (compression)
		if labelLen&0xC0 == 0xC0 {
			offset += 2
			break
		}

		offset++
		if offset+labelLen > len(data) {
			break
		}

		parts = append(parts, string(data[offset:offset+labelLen]))
		offset += labelLen
	}

	name = strings.Join(parts, ".")

	// Read QTYPE (2 bytes)
	if offset+2 <= len(data) {
		qtype = binary.BigEndian.Uint16(data[offset : offset+2])
	}

	return name, qtype
}

func dnsTypeName(t uint16) string {
	switch t {
	case dnsTypeA:
		return "A"
	case dnsTypeNS:
		return "NS"
	case dnsTypeCNAME:
		return "CNAME"
	case dnsTypeSOA:
		return "SOA"
	case dnsTypeMX:
		return "MX"
	case dnsTypeTXT:
		return "TXT"
	case dnsTypeAAAA:
		return "AAAA"
	case dnsTypeSRV:
		return "SRV"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

func dnsRcodeName(code int) string {
	switch code {
	case dnsRcodeNoError:
		return "NOERROR"
	case dnsRcodeFormErr:
		return "FORMERR"
	case dnsRcodeServFail:
		return "SERVFAIL"
	case dnsRcodeNXDomain:
		return "NXDOMAIN"
	case dnsRcodeNotImpl:
		return "NOTIMP"
	case dnsRcodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", code)
	}
}
