// Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
// Use of this source code is governed by the Business Source License
// included in the LICENSE file of this repository.

package conntrack

import (
	"testing"
	"time"
)

func TestTrackerRegisterLookup(t *testing.T) {
	tr := NewTracker()

	info := tr.Register(1234, 5, 0x0100007f, 8080) // 127.0.0.1:8080
	if info == nil {
		t.Fatal("Register returned nil")
	}

	if info.RemoteAddrStr() != "127.0.0.1" {
		t.Errorf("RemoteAddrStr() = %q, want 127.0.0.1", info.RemoteAddrStr())
	}
	if info.RemotePort != 8080 {
		t.Errorf("RemotePort = %d, want 8080", info.RemotePort)
	}

	// Lookup should return the same connection
	found := tr.Lookup(1234, 5)
	if found == nil {
		t.Fatal("Lookup returned nil")
	}
	if found.PID != 1234 {
		t.Errorf("PID = %d, want 1234", found.PID)
	}

	// Different PID should not find it
	if tr.Lookup(9999, 5) != nil {
		t.Error("Lookup should return nil for unknown PID")
	}
}

func TestTrackerRemove(t *testing.T) {
	tr := NewTracker()
	tr.Register(100, 3, 0, 80)

	if tr.Count() != 1 {
		t.Fatalf("Count = %d, want 1", tr.Count())
	}

	info := tr.Remove(100, 3)
	if info == nil {
		t.Fatal("Remove returned nil")
	}

	if tr.Count() != 0 {
		t.Errorf("Count = %d, want 0", tr.Count())
	}

	if tr.Lookup(100, 3) != nil {
		t.Error("Lookup should return nil after Remove")
	}
}

func TestTrackerBytes(t *testing.T) {
	tr := NewTracker()
	tr.Register(100, 3, 0, 80)

	tr.AddBytesSent(100, 3, 500)
	tr.AddBytesSent(100, 3, 300)
	tr.AddBytesRecv(100, 3, 1000)

	info := tr.Lookup(100, 3)
	if info.BytesSent != 800 {
		t.Errorf("BytesSent = %d, want 800", info.BytesSent)
	}
	if info.BytesRecv != 1000 {
		t.Errorf("BytesRecv = %d, want 1000", info.BytesRecv)
	}
}

func TestTrackerCleanStale(t *testing.T) {
	tr := NewTracker()
	info := tr.Register(100, 3, 0, 80)
	info.ConnectTime = time.Now().Add(-10 * time.Minute) // Make it old

	tr.Register(200, 4, 0, 443) // This one is fresh

	removed := tr.CleanStale(5 * time.Minute)
	if removed != 1 {
		t.Errorf("removed = %d, want 1", removed)
	}
	if tr.Count() != 1 {
		t.Errorf("Count = %d, want 1", tr.Count())
	}
}
