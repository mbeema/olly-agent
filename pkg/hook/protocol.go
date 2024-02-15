package hook

import (
	"encoding/binary"
	"fmt"
)

// Message types matching the C header msg_type field.
const (
	MsgConnect = 1
	MsgDataOut = 2
	MsgDataIn  = 3
	MsgClose   = 4
	MsgSSLOut  = 5
	MsgSSLIn   = 6
	MsgAccept  = 7 // R2.3: Inbound connection via accept()
)

// HeaderSize is the fixed size of the binary wire protocol header.
const HeaderSize = 32

// MaxPayload is the maximum payload per message.
const MaxPayload = 16 * 1024

// Header is the Go representation of msg_header_t from libolly.c.
type Header struct {
	MsgType    uint8
	PID        uint32
	TID        uint32
	FD         int32
	PayloadLen uint32
	TimestampNS uint64
}

// Message is a complete hook event with header and optional payload.
type Message struct {
	Header  Header
	Payload []byte
}

// MsgTypeName returns a human-readable name for a message type.
func MsgTypeName(t uint8) string {
	switch t {
	case MsgConnect:
		return "CONNECT"
	case MsgDataOut:
		return "DATA_OUT"
	case MsgDataIn:
		return "DATA_IN"
	case MsgClose:
		return "CLOSE"
	case MsgSSLOut:
		return "SSL_OUT"
	case MsgSSLIn:
		return "SSL_IN"
	case MsgAccept:
		return "ACCEPT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

// IsOutbound returns true if the message contains outbound data.
func (m *Message) IsOutbound() bool {
	return m.Header.MsgType == MsgDataOut || m.Header.MsgType == MsgSSLOut
}

// IsInbound returns true if the message contains inbound data.
func (m *Message) IsInbound() bool {
	return m.Header.MsgType == MsgDataIn || m.Header.MsgType == MsgSSLIn
}

// IsSSL returns true if the message was captured from SSL/TLS functions.
func (m *Message) IsSSL() bool {
	return m.Header.MsgType == MsgSSLOut || m.Header.MsgType == MsgSSLIn
}

// ParseHeader decodes a 32-byte binary header.
func ParseHeader(buf []byte) (Header, error) {
	if len(buf) < HeaderSize {
		return Header{}, fmt.Errorf("buffer too small: %d < %d", len(buf), HeaderSize)
	}

	return Header{
		MsgType:     buf[0],
		PID:         binary.LittleEndian.Uint32(buf[4:8]),
		TID:         binary.LittleEndian.Uint32(buf[8:12]),
		FD:          int32(binary.LittleEndian.Uint32(buf[12:16])),
		PayloadLen:  binary.LittleEndian.Uint32(buf[16:20]),
		TimestampNS: binary.LittleEndian.Uint64(buf[24:32]),
	}, nil
}

// ParseMessage decodes a complete message from a byte buffer.
func ParseMessage(buf []byte) (*Message, error) {
	hdr, err := ParseHeader(buf)
	if err != nil {
		return nil, err
	}

	msg := &Message{Header: hdr}

	if hdr.PayloadLen > 0 {
		if uint32(len(buf)) < uint32(HeaderSize)+hdr.PayloadLen {
			return nil, fmt.Errorf("payload truncated: have %d, need %d",
				len(buf)-HeaderSize, hdr.PayloadLen)
		}
		msg.Payload = make([]byte, hdr.PayloadLen)
		copy(msg.Payload, buf[HeaderSize:HeaderSize+hdr.PayloadLen])
	}

	return msg, nil
}
