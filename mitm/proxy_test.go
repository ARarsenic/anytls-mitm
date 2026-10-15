package mitm

import (
	"testing"
	"time"
)

func TestProxy_ConcurrencyLimits(t *testing.T) {
	cfg := ProxyConfig{
		MaxConns:      3,
		MaxConnsPerIP: 2,
	}
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("Failed to create proxy: %v", err)
	}
	defer p.Stop()

	// IP A connection 1: OK
	if !p.acquireConn("192.168.137.10") {
		t.Fatalf("Expected conn 1 to succeed")
	}
	// IP A connection 2: OK
	if !p.acquireConn("192.168.137.10") {
		t.Fatalf("Expected conn 2 to succeed")
	}
	// IP A connection 3: Should be rejected by per-IP limit (MaxConnsPerIP=2)
	if p.acquireConn("192.168.137.10") {
		t.Fatalf("Expected conn 3 from same IP to be rejected")
	}

	// IP B connection 1: OK (total conns now 3 = MaxConns)
	if !p.acquireConn("192.168.137.20") {
		t.Fatalf("Expected conn from IP B to succeed")
	}

	// IP C connection 1: Should be rejected by total MaxConns limit (3)
	if p.acquireConn("192.168.137.30") {
		t.Fatalf("Expected conn from IP C to be rejected by total MaxConns limit")
	}

	// Release one connection from IP A
	p.releaseConn("192.168.137.10")

	// Now IP C connection should succeed
	if !p.acquireConn("192.168.137.30") {
		t.Fatalf("Expected conn from IP C to succeed after release")
	}
}

func TestConfirmedAnyTLSCache_TTLExpiration(t *testing.T) {
	cache := NewConfirmedAnyTLSCache(10, 50*time.Millisecond)

	cache.Add("1.1.1.1:8443")
	if !cache.Contains("1.1.1.1:8443") {
		t.Fatalf("Expected cache to contain address")
	}

	time.Sleep(70 * time.Millisecond)

	if cache.Contains("1.1.1.1:8443") {
		t.Fatalf("Expected address to have expired from cache")
	}
}
