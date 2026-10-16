package mitm

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// AnyTLS Command Definitions according to official anytls-go protocol
const (
	CmdWaste               uint8 = 0  // Paddings
	CmdSYN                 uint8 = 1  // Stream open
	CmdPSH                 uint8 = 2  // Data push
	CmdFIN                 uint8 = 3  // Stream close (EOF mark)
	CmdSettings            uint8 = 4  // Client settings
	CmdAlert               uint8 = 5  // Server alert rejection
	CmdUpdatePaddingScheme uint8 = 6  // Update padding scheme
	CmdSYNACK              uint8 = 7  // Server stream open report / error
	CmdHeartRequest        uint8 = 8  // Keep-alive request
	CmdHeartResponse       uint8 = 9  // Keep-alive response
	CmdServerSettings      uint8 = 10 // Server settings (v=2)

	// Aliases for compatibility
	CmdPing uint8 = 8
	CmdPong uint8 = 9
	CmdRST  uint8 = 3

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
	// In AnyTLS, the initial frame commands defined by anytls protocol are:
	// - CmdSettings (4, streamID == 0)
	// - CmdWaste (0, streamID == 0)
	// - CmdPing (5, streamID == 0)
	// - CmdPong (6, streamID == 0)
	// - CmdSYN (1)
	isAnyTLS := false
	if (cmd == CmdSettings && streamID == 0) ||
		(cmd == CmdWaste && streamID == 0) ||
		(cmd == CmdPing && streamID == 0) ||
		(cmd == CmdPong && streamID == 0) ||
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

// AnyTLSCommandName returns human-readable name of an AnyTLS command.
func AnyTLSCommandName(cmd uint8) string {
	switch cmd {
	case CmdWaste:
		return "cmdWaste"
	case CmdSYN:
		return "cmdSYN"
	case CmdPSH:
		return "cmdPSH"
	case CmdFIN:
		return "cmdFIN"
	case CmdSettings:
		return "cmdSettings"
	case CmdAlert:
		return "cmdAlert"
	case CmdUpdatePaddingScheme:
		return "cmdUpdatePaddingScheme"
	case CmdSYNACK:
		return "cmdSYNACK"
	case CmdHeartRequest:
		return "cmdHeartRequest"
	case CmdHeartResponse:
		return "cmdHeartResponse"
	case CmdServerSettings:
		return "cmdServerSettings"
	default:
		return fmt.Sprintf("cmdUnknown(%d)", cmd)
	}
}

// ParseSocksAddr parses a SocksAddr byte slice (RFC 1928) into "host:port".
func ParseSocksAddr(b []byte) string {
	if len(b) < 1 {
		return ""
	}
	switch b[0] {
	case 1: // IPv4 (1 + 4 + 2 = 7 bytes)
		if len(b) >= 7 {
			ip := net.IP(b[1:5])
			port := binary.BigEndian.Uint16(b[5:7])
			return fmt.Sprintf("%s:%d", ip.String(), port)
		}
	case 3: // Domain name (1 + 1 + N + 2 bytes)
		if len(b) >= 2 {
			dlen := int(b[1])
			if len(b) >= 2+dlen+2 {
				domain := string(b[2 : 2+dlen])
				port := binary.BigEndian.Uint16(b[2+dlen : 2+dlen+2])
				return fmt.Sprintf("%s:%d", domain, port)
			}
		}
	case 4: // IPv6 (1 + 16 + 2 = 19 bytes)
		if len(b) >= 19 {
			ip := net.IP(b[1:17])
			port := binary.BigEndian.Uint16(b[17:19])
			return fmt.Sprintf("[%s]:%d", ip.String(), port)
		}
	}
	return ""
}

// DescribeAnyTLSChunk walks through an AnyTLS packet/stream chunk and returns human-readable frame summaries.
func DescribeAnyTLSChunk(b []byte, isClientFirstPacket bool) []string {
	var descriptions []string
	offset := 0
	if isClientFirstPacket {
		if len(b) < MinFirstPacketHeaderLen {
			return []string{fmt.Sprintf("AuthHeader(Incomplete: %d bytes)", len(b))}
		}
		l0 := int(binary.BigEndian.Uint16(b[32:34]))
		offset = MinFirstPacketHeaderLen + l0
		descriptions = append(descriptions, fmt.Sprintf("AuthHeader(Hash=%x..., PadLen=%d)", b[:8], l0))
		if offset > len(b) {
			descriptions = append(descriptions, fmt.Sprintf("TruncatedPadding0(have=%d, need=%d)", len(b), offset))
			return descriptions
		}
	}

	for offset+7 <= len(b) {
		cmd := b[offset]
		sid := binary.BigEndian.Uint32(b[offset+1 : offset+5])
		dlen := int(binary.BigEndian.Uint16(b[offset+5 : offset+7]))
		frameTotal := 7 + dlen
		cmdName := AnyTLSCommandName(cmd)

		if offset+frameTotal > len(b) {
			descriptions = append(descriptions, fmt.Sprintf("%s(Stream=%d, NeedLen=%d, RemainingBytes=%d)",
				cmdName, sid, dlen, len(b)-offset-7))
			break
		}

		payload := b[offset+7 : offset+frameTotal]
		var detail string
		switch cmd {
		case CmdSettings, CmdServerSettings:
			detail = strings.ReplaceAll(string(payload), "\n", " ")
		case CmdAlert:
			detail = fmt.Sprintf("ALERT: %q", string(payload))
		case CmdSYNACK:
			if dlen > 0 {
				detail = fmt.Sprintf("ERROR: %q", string(payload))
			} else {
				detail = "SUCCESS"
			}
		case CmdPSH:
			if addr := ParseSocksAddr(payload); addr != "" {
				detail = fmt.Sprintf("Target: %s", addr)
			} else if len(payload) >= 4 && (string(payload[:4]) == "HTTP" || string(payload[:4]) == "GET " || string(payload[:4]) == "POST") {
				firstLine := strings.SplitN(string(payload), "\r\n", 2)[0]
				detail = fmt.Sprintf("HTTP: %q", firstLine)
			} else {
				detail = fmt.Sprintf("%d bytes data", dlen)
			}
		default:
			if dlen > 0 {
				detail = fmt.Sprintf("%d bytes", dlen)
			}
		}

		if detail != "" {
			descriptions = append(descriptions, fmt.Sprintf("%s(Stream=%d, %s)", cmdName, sid, detail))
		} else {
			descriptions = append(descriptions, fmt.Sprintf("%s(Stream=%d)", cmdName, sid))
		}

		offset += frameTotal
	}

	return descriptions
}
