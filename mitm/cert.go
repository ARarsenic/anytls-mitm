package mitm

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

type certCacheEntry struct {
	key       string
	cert      *tls.Certificate
	expiresAt time.Time
}

// CertCloner handles in-memory ECDSA key management and 1:1 dynamic X.509
// certificate cloning from upstream TLS servers with bounded LRU eviction and TTL (H-02 fix).
type CertCloner struct {
	mu         sync.Mutex
	privateKey *ecdsa.PrivateKey
	cache      map[string]*list.Element
	lru        *list.List
	maxEntries int
	defaultTTL time.Duration
}

// NewCertCloner initializes a new CertCloner with a generated ECDSA P-256 private key.
func NewCertCloner() (*CertCloner, error) {
	return NewCertClonerWithCapacity(1000, 24*time.Hour)
}

// NewCertClonerWithCapacity initializes a CertCloner with specified max entries and TTL.
func NewCertClonerWithCapacity(maxEntries int, defaultTTL time.Duration) (*CertCloner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate in-memory ECDSA private key: %w", err)
	}

	if maxEntries <= 0 {
		maxEntries = 1000
	}
	if defaultTTL <= 0 {
		defaultTTL = 24 * time.Hour
	}

	return &CertCloner{
		privateKey: key,
		cache:      make(map[string]*list.Element),
		lru:        list.New(),
		maxEntries: maxEntries,
		defaultTTL: defaultTTL,
	}, nil
}

// Get returns a cached cloned certificate for the given cacheKey if available and not expired.
func (c *CertCloner) Get(cacheKey string) *tls.Certificate {
	if cacheKey == "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.cache[cacheKey]
	if !ok {
		return nil
	}

	entry := elem.Value.(*certCacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.lru.Remove(elem)
		delete(c.cache, cacheKey)
		return nil
	}

	c.lru.MoveToFront(elem)
	return entry.cert
}

// Clear flushes all cached certificates.
func (c *CertCloner) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]*list.Element)
	c.lru.Init()
}

// Len returns the current count of cached certificates.
func (c *CertCloner) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cache)
}

// Clone clones an upstream X.509 certificate and signs it with the local ECDSA private key.
// Cloned certificates are cached by cacheKey (e.g. OriginalDstIP:Port).
func (c *CertCloner) Clone(upstreamCert *x509.Certificate, cacheKey string, sni string) (*tls.Certificate, error) {
	if cacheKey != "" {
		c.mu.Lock()
		if elem, ok := c.cache[cacheKey]; ok {
			entry := elem.Value.(*certCacheEntry)
			if time.Now().Before(entry.expiresAt) {
				c.lru.MoveToFront(elem)
				cert := entry.cert
				c.mu.Unlock()
				return cert, nil
			}
			c.lru.Remove(elem)
			delete(c.cache, cacheKey)
		}
		c.mu.Unlock()
	}

	serial := upstreamCert.SerialNumber
	if serial == nil {
		serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		var err error
		serial, err = rand.Int(rand.Reader, serialLimit)
		if err != nil {
			serial = big.NewInt(time.Now().UnixNano())
		}
	}

	dnsNames := append([]string{}, upstreamCert.DNSNames...)
	var ipAddresses []net.IP
	for _, ip := range upstreamCert.IPAddresses {
		ipAddresses = append(ipAddresses, ip)
	}

	// If SNI was specified by client, ensure it is covered in SAN
	if sni != "" {
		if parsedIP := net.ParseIP(sni); parsedIP != nil {
			found := false
			for _, existingIP := range ipAddresses {
				if existingIP.Equal(parsedIP) {
					found = true
					break
				}
			}
			if !found {
				ipAddresses = append(ipAddresses, parsedIP)
			}
		} else {
			found := false
			for _, name := range dnsNames {
				if name == sni {
					found = true
					break
				}
			}
			if !found {
				dnsNames = append(dnsNames, sni)
			}
		}
	}

	// 1:1 certificate cloning
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               upstreamCert.Subject,
		NotBefore:             upstreamCert.NotBefore,
		NotAfter:              upstreamCert.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &c.privateKey.PublicKey, c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign cloned certificate: %w", err)
	}

	clonedCert := &tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  c.privateKey,
	}

	if cacheKey != "" {
		c.mu.Lock()
		expiresAt := time.Now().Add(c.defaultTTL)
		if !upstreamCert.NotAfter.IsZero() && upstreamCert.NotAfter.After(time.Now()) && upstreamCert.NotAfter.Before(expiresAt) {
			expiresAt = upstreamCert.NotAfter
		}

		if elem, ok := c.cache[cacheKey]; ok {
			c.lru.MoveToFront(elem)
			elem.Value = &certCacheEntry{
				key:       cacheKey,
				cert:      clonedCert,
				expiresAt: expiresAt,
			}
		} else {
			// Enforce max capacity by evicting oldest
			if c.lru.Len() >= c.maxEntries {
				oldest := c.lru.Back()
				if oldest != nil {
					c.lru.Remove(oldest)
					oldEntry := oldest.Value.(*certCacheEntry)
					delete(c.cache, oldEntry.key)
				}
			}
			newEntry := &certCacheEntry{
				key:       cacheKey,
				cert:      clonedCert,
				expiresAt: expiresAt,
			}
			elem := c.lru.PushFront(newEntry)
			c.cache[cacheKey] = elem
		}
		c.mu.Unlock()
	}

	return clonedCert, nil
}
