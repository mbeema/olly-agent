package hook

import (
	"encoding/binary"
	"testing"
)

func TestParseHeader(t *testing.T) {
	buf := make([]byte, HeaderSize)
	buf[0] = MsgConnect                                // msg_type
	binary.LittleEndian.PutUint32(buf[4:8], 12345)     // pid
	binary.LittleEndian.PutUint32(buf[8:12], 67890)    // tid
	binary.LittleEndian.PutUint32(buf[12:16], 5)       // fd
	binary.LittleEndian.PutUint32(buf[16:20], 100)     // payload_len
	binary.LittleEndian.PutUint64(buf[24:32], 1000000) // timestamp

	hdr, err := ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader error: %v", err)
	}

	if hdr.MsgType != MsgConnect {
		t.Errorf("MsgType = %d, want %d", hdr.MsgType, MsgConnect)
	}
	if hdr.PID != 12345 {
		t.Errorf("PID = %d, want 12345", hdr.PID)
	}
	if hdr.TID != 67890 {
		t.Errorf("TID = %d, want 67890", hdr.TID)
	}
	if hdr.FD != 5 {
		t.Errorf("FD = %d, want 5", hdr.FD)
	}
	if hdr.PayloadLen != 100 {
		t.Errorf("PayloadLen = %d, want 100", hdr.PayloadLen)
	}
	if hdr.TimestampNS != 1000000 {
		t.Errorf("TimestampNS = %d, want 1000000", hdr.TimestampNS)
	}
}

func TestParseMessage(t *testing.T) {
	payload := []byte("Hello, World!")
	buf := make([]byte, HeaderSize+len(payload))

	buf[0] = MsgDataOut
	binary.LittleEndian.PutUint32(buf[4:8], 100)
	binary.LittleEndian.PutUint32(buf[8:12], 200)
	binary.LittleEndian.PutUint32(buf[12:16], 3)
	binary.LittleEndian.PutUint32(buf[16:20], uint32(len(payload)))
	copy(buf[HeaderSize:], payload)

	msg, err := ParseMessage(buf)
	if err != nil {
		t.Fatalf("ParseMessage error: %v", err)
	}

	if !msg.IsOutbound() {
		t.Error("expected outbound message")
	}
	if msg.IsInbound() {
		t.Error("should not be inbound")
	}
	if string(msg.Payload) != "Hello, World!" {
		t.Errorf("payload = %q", msg.Payload)
	}
}

func TestMsgTypeName(t *testing.T) {
	tests := []struct {
		t    uint8
		name string
	}{
		{MsgConnect, "CONNECT"},
		{MsgDataOut, "DATA_OUT"},
		{MsgDataIn, "DATA_IN"},
		{MsgClose, "CLOSE"},
		{MsgSSLOut, "SSL_OUT"},
		{MsgSSLIn, "SSL_IN"},
		{99, "UNKNOWN(99)"},
	}

	for _, tt := range tests {
		got := MsgTypeName(tt.t)
		if got != tt.name {
			t.Errorf("MsgTypeName(%d) = %q, want %q", tt.t, got, tt.name)
		}
	}
}

func TestMessageSSL(t *testing.T) {
	msg := &Message{Header: Header{MsgType: MsgSSLOut}}
	if !msg.IsSSL() {
		t.Error("expected SSL")
	}
	if !msg.IsOutbound() {
		t.Error("expected outbound")
	}

	msg2 := &Message{Header: Header{MsgType: MsgSSLIn}}
	if !msg2.IsSSL() {
		t.Error("expected SSL")
	}
	if !msg2.IsInbound() {
		t.Error("expected inbound")
	}
}
