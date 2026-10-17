package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func generateTestCert(commonName string) (*tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:  []string{commonName, "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(1 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}

func TestUpstreamPool_Basic(t *testing.T) {
	cert, err := generateTestCert("test-server.local")
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				buf := make([]byte, 1024)
				for {
					if _, err := conn.Read(buf); err != nil {
						_ = conn.Close()
						return
					}
				}
			}(c)
		}
	}()

	addr := ln.Addr().String()
	pool := NewUpstreamPool(2, 5*time.Second)
	defer pool.Stop()

	// Record target to trigger background pre-warming
	pool.RecordTarget(addr, "test-server.local", nil)

	// Wait up to 500ms for background replenishment
	var conn *tls.Conn
	for i := 0; i < 20; i++ {
		conn = pool.Get(addr)
		if conn != nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if conn == nil {
		t.Fatalf("expected pre-warmed connection from pool, got nil")
	}
	defer conn.Close()

	if conn.ConnectionState().HandshakeComplete != true {
		t.Errorf("expected pre-warmed connection to have completed handshake")
	}
}

func TestUpstreamPool_ConcurrentReplenish(t *testing.T) {
	cert, err := generateTestCert("concurrent-server.local")
	if err != nil {
		t.Fatalf("failed to generate cert: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{*cert},
	})
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				buf := make([]byte, 1024)
				for {
					if _, err := conn.Read(buf); err != nil {
						_ = conn.Close()
						return
					}
				}
			}(c)
		}
	}()

	addr := ln.Addr().String()
	pool := NewUpstreamPool(6, 5*time.Second)
	defer pool.Stop()

	// Trigger concurrent pre-warming
	pool.RecordTarget(addr, "concurrent-server.local", nil)

	// Wait up to 1 second for all 6 connections to be replenished concurrently
	var conns []*tls.Conn
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		for len(conns) < 6 {
			c := pool.Get(addr)
			if c == nil {
				break
			}
			conns = append(conns, c)
		}
		if len(conns) >= 6 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, c := range conns {
		defer c.Close()
	}

	if len(conns) < 4 {
		t.Fatalf("expected at least 4 concurrent pre-warmed connections, got %d", len(conns))
	}
}

