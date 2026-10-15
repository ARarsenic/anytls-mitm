package mitm

import (
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

// CertCloner handles in-memory ECDSA key management and 1:1 dynamic X.509
// certificate cloning from upstream TLS servers.
type CertCloner struct {
	mu         sync.RWMutex
	privateKey *ecdsa.PrivateKey
	cache      map[string]*tls.Certificate
}

// NewCertCloner initializes a new CertCloner with a generated ECDSA P-256 private key.
func NewCertCloner() (*CertCloner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate in-memory ECDSA private key: %w", err)
	}

	return &CertCloner{
		privateKey: key,
		cache:      make(map[string]*tls.Certificate),
	}, nil
}

// Get returns a cached cloned certificate for the given cacheKey if available.
func (c *CertCloner) Get(cacheKey string) *tls.Certificate {
	if cacheKey == "" {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache[cacheKey]
}

// Clone clones an upstream X.509 certificate and signs it with the local ECDSA private key.
// Cloned certificates are cached by cacheKey (e.g. OriginalDstIP:Port).
func (c *CertCloner) Clone(upstreamCert *x509.Certificate, cacheKey string, sni string) (*tls.Certificate, error) {
	if cacheKey != "" {
		c.mu.RLock()
		if cached, ok := c.cache[cacheKey]; ok {
			c.mu.RUnlock()
			return cached, nil
		}
		c.mu.RUnlock()
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
		c.cache[cacheKey] = clonedCert
		c.mu.Unlock()
	}

	return clonedCert, nil
}
