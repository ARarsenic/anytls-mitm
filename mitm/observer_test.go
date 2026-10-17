package mitm

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"testing/iotest"
)

func TestInspectionReaderFragmentedSettingsPreservesStream(t *testing.T) {
	settings := []byte("v=2\nclient=test-client\npadding-md5=test-md5\n")
	packet := buildAnyTLSInitialPacket("test-password", 30, CmdSettings, 0, uint16(len(settings)))
	packet = append(packet[:34+30+7], settings...)
	payload := append(bytes.Clone(packet), bytes.Repeat([]byte("application-data"), 10000)...)
	calls := 0
	r := &inspectionReader{
		source: iotest.OneByteReader(bytes.NewReader(payload)),
		report: func(matched bool, hash []byte, meta *AnyTLSMetadata) {
			calls++
			if !matched || !bytes.Equal(hash, packet[:32]) {
				t.Error("authentication not detected")
			}
			if meta == nil || meta.Version != "2" || meta.ClientApp != "test-client" || meta.PaddingMD5 != "test-md5" {
				t.Errorf("incomplete settings: %+v", meta)
			}
		},
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("relay lost or changed bytes")
	}
	if calls != 1 || r.prefix != nil {
		t.Fatalf("inspection did not finish and release prefix: calls=%d", calls)
	}
}

func TestInspectionReaderRejectsOversizedPrefixWithoutBlocking(t *testing.T) {
	payload := make([]byte, MaxInspectBufferSize+100)
	binary.BigEndian.PutUint16(payload[32:34], 65535)
	calls := 0
	r := &inspectionReader{source: bytes.NewReader(payload), report: func(matched bool, _ []byte, _ *AnyTLSMetadata) {
		calls++
		if matched {
			t.Error("oversized prefix matched")
		}
	}}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("relay failed: %v", err)
	}
	if calls != 1 || r.prefix != nil {
		t.Fatal("prefix not released")
	}
}
