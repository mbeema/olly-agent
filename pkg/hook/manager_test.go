// Copyright 2024-2026 Madhukar Beema. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package hook

import (
	"encoding/binary"
	"testing"
)

func TestDispatchLogWrite(t *testing.T) {
	var gotPID, gotTID uint32
	var gotFD int32
	var gotData []byte
	var gotTS uint64
	called := false

	m := &Manager{
		callbacks: Callbacks{
			OnLogWrite: func(pid, tid uint32, fd int32, data []byte, ts uint64) {
				called = true
				gotPID = pid
				gotTID = tid
				gotFD = fd
				gotData = data
				gotTS = ts
			},
		},
	}

	payload := []byte("ERROR: something failed\n")
	buf := make([]byte, HeaderSize+len(payload))
	buf[0] = MsgLogWrite
	binary.LittleEndian.PutUint32(buf[4:8], 1234)
	binary.LittleEndian.PutUint32(buf[8:12], 5678)
	binary.LittleEndian.PutUint32(buf[12:16], 3) // fd=3 (log file)
	binary.LittleEndian.PutUint32(buf[16:20], uint32(len(payload)))
	binary.LittleEndian.PutUint64(buf[24:32], 42000)
	copy(buf[HeaderSize:], payload)

	msg, err := ParseMessage(buf)
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}

	m.dispatch(msg)

	if !called {
		t.Fatal("OnLogWrite callback was not called")
	}
	if gotPID != 1234 {
		t.Errorf("PID = %d, want 1234", gotPID)
	}
	if gotTID != 5678 {
		t.Errorf("TID = %d, want 5678", gotTID)
	}
	if gotFD != 3 {
		t.Errorf("FD = %d, want 3", gotFD)
	}
	if string(gotData) != string(payload) {
		t.Errorf("data = %q, want %q", gotData, payload)
	}
	if gotTS != 42000 {
		t.Errorf("TS = %d, want 42000", gotTS)
	}
}

func TestDispatchLogWriteEmptyPayload(t *testing.T) {
	called := false
	m := &Manager{
		callbacks: Callbacks{
			OnLogWrite: func(pid, tid uint32, fd int32, data []byte, ts uint64) {
				called = true
			},
		},
	}

	// MsgLogWrite with empty payload should NOT call the callback
	msg := &Message{
		Header: Header{
			MsgType:    MsgLogWrite,
			PID:        100,
			TID:        200,
			FD:         5,
			PayloadLen: 0,
		},
		Payload: nil,
	}

	m.dispatch(msg)

	if called {
		t.Error("OnLogWrite should not be called with empty payload")
	}
}

func TestDispatchLogWriteNilCallback(t *testing.T) {
	m := &Manager{
		callbacks: Callbacks{
			// OnLogWrite is nil
		},
	}

	msg := &Message{
		Header: Header{
			MsgType:    MsgLogWrite,
			PID:        100,
			TID:        200,
			FD:         5,
			PayloadLen: 5,
		},
		Payload: []byte("hello"),
	}

	// Should not panic
	m.dispatch(msg)
}
