package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func generateDummyCert(subject string, validDuration time.Duration) *x509.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: subject,
		},
		NotBefore: time.Now().Add(-1 * time.Minute),
		NotAfter:  time.Now().Add(validDuration),
	}
	der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}

func TestCertCloner_LRUEviction(t *testing.T) {
	// Initialize cloner with max 2 entries
	cloner, err := NewCertClonerWithCapacity(2, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to create cloner: %v", err)
	}

	cert1 := generateDummyCert("host1.com", 1*time.Hour)
	cert2 := generateDummyCert("host2.com", 1*time.Hour)
	cert3 := generateDummyCert("host3.com", 1*time.Hour)

	_, err = cloner.Clone(cert1, "key1", "host1.com")
	if err != nil {
		t.Fatalf("Clone 1 failed: %v", err)
	}
	_, err = cloner.Clone(cert2, "key2", "host2.com")
	if err != nil {
		t.Fatalf("Clone 2 failed: %v", err)
	}

	if cloner.Len() != 2 {
		t.Fatalf("Expected 2 cached certs, got %d", cloner.Len())
	}

	// Access key1 to make it most recently used
	if cloner.Get("key1") == nil {
		t.Fatalf("Expected key1 to be present")
	}

	// Adding key3 should evict key2 (the least recently used)
	_, err = cloner.Clone(cert3, "key3", "host3.com")
	if err != nil {
		t.Fatalf("Clone 3 failed: %v", err)
	}

	if cloner.Len() != 2 {
		t.Fatalf("Expected 2 cached certs after eviction, got %d", cloner.Len())
	}

	if cloner.Get("key1") == nil {
		t.Errorf("Expected key1 to remain in cache")
	}
	if cloner.Get("key2") != nil {
		t.Errorf("Expected key2 to have been evicted")
	}
	if cloner.Get("key3") == nil {
		t.Errorf("Expected key3 to be present")
	}
}

func TestCertCloner_TTLExpiration(t *testing.T) {
	// Initialize cloner with 50ms TTL
	cloner, err := NewCertClonerWithCapacity(10, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create cloner: %v", err)
	}

	cert := generateDummyCert("expire.com", 1*time.Hour)
	_, err = cloner.Clone(cert, "expireKey", "expire.com")
	if err != nil {
		t.Fatalf("Clone failed: %v", err)
	}

	if cloner.Get("expireKey") == nil {
		t.Fatalf("Expected key to be present before expiration")
	}

	time.Sleep(70 * time.Millisecond)

	if cloner.Get("expireKey") != nil {
		t.Errorf("Expected key to have expired and return nil")
	}
}
