package mitm

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// AnyTLS Command Definitions according to anytls-go protocol
const (
	CmdWaste    uint8 = 0
	CmdSYN      uint8 = 1
	CmdFIN      uint8 = 2
	CmdRST      uint8 = 3
	CmdSettings uint8 = 4
	CmdPing     uint8 = 5
	CmdPong     uint8 = 6

	MinFirstPacketHeaderLen = 34 // 32 bytes auth hash + 2 bytes padding length
	MaxInspectBufferSize    = 65536
)

var (
	// Plaintext HTTP prefixes to reject early
	httpPrefixes = [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("HEAD "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("OPTIONS "),
		[]byte("CONNECT "),
		[]byte("PRI * HTTP/2.0"),
	}
)

// AnyTLSMetadata holds extracted session and client metadata from an AnyTLS handshake.
type AnyTLSMetadata struct {
	ClientApp   string // e.g. "sing-box 1.10.0", "mihomo/1.18.0", "anytls-go/0.0.1"
	Version     string // e.g. "2"
	PaddingMD5  string // e.g. "34f19b..."
	Padding0Len int
}

// InspectAnyTLS performs non-destructive inspection on the decrypted stream reader,
// returning match status, auth hash, and parsed AnyTLS session metadata.
func InspectAnyTLS(br *bufio.Reader) (bool, []byte, *AnyTLSMetadata, error) {
	// Step 1: Peek at least 34 bytes (AuthHash + Padding0 length)
	buf, err := br.Peek(MinFirstPacketHeaderLen)
	if err != nil {
		return false, nil, nil, fmt.Errorf("failed to peek initial header: %w", err)
	}

	// Step 2: Reject obvious HTTP/1.x and HTTP/2 plaintext prefixes
	for _, prefix := range httpPrefixes {
		if bytes.HasPrefix(buf, prefix) {
			return false, nil, nil, nil
		}
	}

	// Step 3: Parse Padding0 length (L0)
	l0 := int(binary.BigEndian.Uint16(buf[32:34]))
	offset := MinFirstPacketHeaderLen + l0
	requiredLen := offset + 7 // Need 7-byte frame header after padding

	if requiredLen > MaxInspectBufferSize {
		return false, nil, nil, nil
	}

	// Step 4: Peek the frame header following padding0
	fullBuf, err := br.Peek(requiredLen)
	if err != nil {
		return false, nil, nil, fmt.Errorf("failed to peek frame header at offset %d: %w", offset, err)
	}

	cmd := fullBuf[offset]
	streamID := binary.BigEndian.Uint32(fullBuf[offset+1 : offset+5])
	dataLen := int(binary.BigEndian.Uint16(fullBuf[offset+5 : offset+7]))

	// Step 5: Check match condition
	// In anytls, the first frame is always:
	// - cmdSettings (cmd == 4 && streamID == 0)
	// - cmdWaste (cmd == 0 && streamID == 0)
	// - cmdSYN (cmd == 1)
	isAnyTLS := false
	if (cmd == CmdSettings && streamID == 0) ||
		(cmd == CmdWaste && streamID == 0) ||
		(cmd == CmdSYN) {
		isAnyTLS = true
	}

	if !isAnyTLS {
		return false, nil, nil, nil
	}

	authHash := make([]byte, 32)
	copy(authHash, fullBuf[:32])

	meta := &AnyTLSMetadata{
		Padding0Len: l0,
		Version:     "1",
	}

	// If first frame is cmdSettings, try to parse client application and protocol version
	if cmd == CmdSettings && dataLen > 0 && requiredLen+dataLen <= MaxInspectBufferSize {
		if settingsBuf, peekErr := br.Peek(requiredLen + dataLen); peekErr == nil {
			settingsData := string(settingsBuf[requiredLen : requiredLen+dataLen])
			lines := strings.Split(settingsData, "\n")
			for _, line := range lines {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					k := strings.TrimSpace(parts[0])
					v := strings.TrimSpace(parts[1])
					switch k {
					case "client":
						meta.ClientApp = v
					case "v":
						meta.Version = v
					case "padding-md5":
						meta.PaddingMD5 = v
					}
				}
			}
		}
	}

	return true, authHash, meta, nil
}

// InspectAnyTLSFirstPacket performs non-destructive first-packet inspection on the
// decrypted stream reader (backward-compatible wrapper).
func InspectAnyTLSFirstPacket(br *bufio.Reader) (bool, []byte, error) {
	matched, hash, _, err := InspectAnyTLS(br)
	return matched, hash, err
}
