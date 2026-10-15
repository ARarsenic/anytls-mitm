package mitm

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// TLSFingerprintInfo represents analyzed fingerprint traits of a TLS ClientHello.
type TLSFingerprintInfo struct {
	HasGREASE       bool
	FingerprintType string
	JA3Raw          string
	JA3Hash         string
	ALPN            []string
}

// IsGREASE checks if a 16-bit TLS parameter is a GREASE value per RFC 8701.
// Values: 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa.
func IsGREASE(val uint16) bool {
	return (val&0x0f0f) == 0x0a0a && ((val >> 8) == (val & 0xff))
}

// AnalyzeTLSFingerprint analyzes ClientHello parameters to identify whether
// the client has enabled uTLS / browser fingerprint mimicry (e.g. Chrome, iOS, Firefox).
func AnalyzeTLSFingerprint(hello *tls.ClientHelloInfo) *TLSFingerprintInfo {
	if hello == nil {
		return &TLSFingerprintInfo{FingerprintType: "Unknown"}
	}

	hasGrease := false
	var filteredCiphers []string
	for _, cs := range hello.CipherSuites {
		if IsGREASE(cs) {
			hasGrease = true
			continue
		}
		filteredCiphers = append(filteredCiphers, strconv.Itoa(int(cs)))
	}

	var filteredCurves []string
	for _, c := range hello.SupportedCurves {
		val := uint16(c)
		if IsGREASE(val) {
			hasGrease = true
			continue
		}
		filteredCurves = append(filteredCurves, strconv.Itoa(int(val)))
	}

	for _, v := range hello.SupportedVersions {
		if IsGREASE(v) {
			hasGrease = true
			break
		}
	}

	var points []string
	for _, p := range hello.SupportedPoints {
		points = append(points, strconv.Itoa(int(p)))
	}

	// Determine client fingerprint type
	var fpType string
	hasH2 := false
	for _, p := range hello.SupportedProtos {
		if p == "h2" {
			hasH2 = true
			break
		}
	}

	if hasGrease {
		// GREASE is a definitive indicator of Chrome/Chromium or Apple Safari/iOS uTLS profiles
		if hasH2 {
			fpType = "uTLS-Chrome / Chromium / Edge"
		} else {
			fpType = "uTLS-Safari / iOS"
		}
	} else {
		// Check for Firefox-specific cipher signature: TLS_AES_128_GCM (0x1301) followed by CHACHA20 (0x1303) before AES_256 (0x1302)
		if len(hello.CipherSuites) >= 3 &&
			hello.CipherSuites[0] == 0x1301 &&
			hello.CipherSuites[1] == 0x1303 &&
			hello.CipherSuites[2] == 0x1302 {
			fpType = "uTLS-Firefox"
		} else {
			fpType = "Standard (No uTLS / Browser Impersonation)"
		}
	}

	// Compute JA3 string representation:
	// SSLVersion,CipherSuites,Extensions(omitted here),EllipticCurves,EllipticCurvePointFormats
	sslVersion := "771" // TLS 1.2 default record layer
	ciphersStr := strings.Join(filteredCiphers, "-")
	curvesStr := strings.Join(filteredCurves, "-")
	pointsStr := strings.Join(points, "-")

	ja3Raw := fmt.Sprintf("%s,%s,,%s,%s", sslVersion, ciphersStr, curvesStr, pointsStr)
	hash := md5.Sum([]byte(ja3Raw))
	ja3Hash := hex.EncodeToString(hash[:])

	return &TLSFingerprintInfo{
		HasGREASE:       hasGrease,
		FingerprintType: fpType,
		JA3Raw:          ja3Raw,
		JA3Hash:         ja3Hash,
		ALPN:            hello.SupportedProtos,
	}
}
