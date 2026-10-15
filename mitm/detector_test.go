package mitm

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

// buildAnyTLSInitialPacket creates a mock AnyTLS initial packet
func buildAnyTLSInitialPacket(password string, paddingLen int, cmd uint8, streamID uint32, dataLen uint16) []byte {
	hash := sha256.Sum256([]byte(password))
	buf := new(bytes.Buffer)

	// 1. AuthHash: 32 bytes
	buf.Write(hash[:])

	// 2. Padding0 length: 2 bytes
	paddingLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(paddingLenBytes, uint16(paddingLen))
	buf.Write(paddingLenBytes)

	// 3. Padding0: paddingLen bytes
	padding := make([]byte, paddingLen)
	for i := range padding {
		padding[i] = byte(i % 256)
	}
	buf.Write(padding)

	// 4. Frame Header: 7 bytes
	buf.WriteByte(cmd)
	streamIDBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(streamIDBytes, streamID)
	buf.Write(streamIDBytes)
	dataLenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(dataLenBytes, dataLen)
	buf.Write(dataLenBytes)

	// Optional dummy payload
	buf.WriteString("hello-world-payload")

	return buf.Bytes()
}

func TestInspectAnyTLSFirstPacket_ValidCases(t *testing.T) {
	testCases := []struct {
		name       string
		password   string
		paddingLen int
		cmd        uint8
		streamID   uint32
	}{
		{
			name:       "Settings frame with zero padding",
			password:   "secret123",
			paddingLen: 0,
			cmd:        CmdSettings,
			streamID:   0,
		},
		{
			name:       "Waste frame with 16 bytes padding",
			password:   "anotherPassword",
			paddingLen: 16,
			cmd:        CmdWaste,
			streamID:   0,
		},
		{
			name:       "SYN frame with 256 bytes padding",
			password:   "securePasswd321",
			paddingLen: 256,
			cmd:        CmdSYN,
			streamID:   1,
		},
		{
			name:       "Settings frame with large padding",
			password:   "myAnyTLSPass",
			paddingLen: 1024,
			cmd:        CmdSettings,
			streamID:   0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rawPkt := buildAnyTLSInitialPacket(tc.password, tc.paddingLen, tc.cmd, tc.streamID, 19)
			br := bufio.NewReaderSize(bytes.NewReader(rawPkt), 65536)

			matched, authHash, err := InspectAnyTLSFirstPacket(br)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !matched {
				t.Fatalf("expected match for %s, but got false", tc.name)
			}

			expectedHash := sha256.Sum256([]byte(tc.password))
			if !bytes.Equal(authHash, expectedHash[:]) {
				t.Fatalf("auth hash mismatch: expected %x, got %x", expectedHash, authHash)
			}

			// Ensure non-destructive: check that Reader still can read the full stream from beginning
			peeked, err := br.Peek(len(rawPkt))
			if err != nil {
				t.Fatalf("failed to peek after inspection: %v", err)
			}
			if !bytes.Equal(peeked, rawPkt) {
				t.Fatalf("reader was altered, peeked data differs from original")
			}
		})
	}
}

func TestInspectAnyTLSFirstPacket_RejectPlaintextHTTP(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "HTTP/1.1 GET",
			data: []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n"),
		},
		{
			name: "HTTP/1.1 POST",
			data: []byte("POST /api/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\"}"),
		},
		{
			name: "HTTP/2 preface",
			data: []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00"),
		},
		{
			name: "Random non-matching binary stream",
			data: func() []byte {
				b := make([]byte, 100)
				for i := range b {
					b[i] = 0xAA
				}
				// Set invalid cmd byte
				b[34] = 99
				return b
			}(),
		},
		{
			name: "Settings frame with non-zero streamID (invalid for settings)",
			data: buildAnyTLSInitialPacket("pass", 0, CmdSettings, 2, 0),
		},
		{
			name: "Waste frame with non-zero streamID (invalid for waste)",
			data: buildAnyTLSInitialPacket("pass", 0, CmdWaste, 5, 0),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			br := bufio.NewReaderSize(bytes.NewReader(tc.data), 65536)
			matched, _, err := InspectAnyTLSFirstPacket(br)
			if err != nil {
				// Some might return error if buffer is too short, which is also a rejection
				return
			}
			if matched {
				t.Fatalf("expected rejection for %s, but got true", tc.name)
			}
		})
	}
}

func TestInspectAnyTLSFirstPacket_Truncated(t *testing.T) {
	shortData := []byte("short")
	br := bufio.NewReader(bytes.NewReader(shortData))
	matched, _, err := InspectAnyTLSFirstPacket(br)
	if matched {
		t.Fatalf("expected match=false on short data")
	}
	if err == nil {
		t.Fatalf("expected error on truncated data")
	}
}
