package mitm

import (
	"crypto/tls"
	"testing"
)

func TestAnalyzeTLSFingerprint_uTLSChrome(t *testing.T) {
	// Simulated uTLS Chrome ClientHello with GREASE
	hello := &tls.ClientHelloInfo{
		CipherSuites: []uint16{
			0x2a2a, // GREASE
			0x1301, // TLS_AES_128_GCM_SHA256
			0x1302, // TLS_AES_256_GCM_SHA384
			0x1303, // TLS_CHACHA20_POLY1305_SHA256
			0xc02b,
		},
		SupportedCurves: []tls.CurveID{
			0x3a3a,       // GREASE
			tls.X25519,
			tls.CurveP256,
		},
		SupportedPoints: []uint8{0},
		SupportedProtos: []string{"h2", "http/1.1"},
	}

	fp := AnalyzeTLSFingerprint(hello)
	if !fp.HasGREASE {
		t.Fatalf("expected HasGREASE to be true")
	}
	if fp.FingerprintType != "uTLS-Chrome / Chromium / Edge" {
		t.Fatalf("expected uTLS-Chrome, got %s", fp.FingerprintType)
	}
	if fp.JA3Hash == "" {
		t.Fatalf("expected non-empty JA3Hash")
	}
}

func TestAnalyzeTLSFingerprint_StandardClient(t *testing.T) {
	// Standard Go crypto/tls ClientHello (no GREASE)
	hello := &tls.ClientHelloInfo{
		CipherSuites: []uint16{
			0x1301,
			0x1302,
			0xc02f,
		},
		SupportedCurves: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		SupportedPoints: []uint8{0},
		SupportedProtos: []string{},
	}

	fp := AnalyzeTLSFingerprint(hello)
	if fp.HasGREASE {
		t.Fatalf("expected HasGREASE to be false for standard client")
	}
	if fp.FingerprintType != "Standard (No uTLS / Browser Impersonation)" {
		t.Fatalf("expected standard client, got %s", fp.FingerprintType)
	}
}
