package divert

import (
	"testing"
	"time"
)

func TestNATTable_GetTTLExpiration(t *testing.T) {
	// 50ms TTL
	nat := NewNATTableWithTTL(50 * time.Millisecond)
	defer nat.Stop()

	clientKey := "192.168.137.50:54321"
	origDst := "1.2.3.4:443"

	nat.Set(clientKey, origDst)

	val, ok := nat.Get(clientKey)
	if !ok || val != origDst {
		t.Fatalf("Expected %s, got %s (ok=%v)", origDst, val, ok)
	}

	// Wait for TTL to expire
	time.Sleep(70 * time.Millisecond)

	// Get must return false because the entry is expired (H-03 fix)
	val, ok = nat.Get(clientKey)
	if ok {
		t.Fatalf("Expected expired entry to return ok=false, got ok=true (val=%s)", val)
	}
}

func TestNATTable_Delete(t *testing.T) {
	nat := NewNATTableWithTTL(1 * time.Minute)
	defer nat.Stop()

	clientKey := "192.168.137.50:54321"
	origDst := "1.2.3.4:443"

	nat.Set(clientKey, origDst)

	if _, ok := nat.Get(clientKey); !ok {
		t.Fatalf("Expected key to exist")
	}

	nat.Delete(clientKey)

	if _, ok := nat.Get(clientKey); ok {
		t.Fatalf("Expected key to be deleted")
	}
}
