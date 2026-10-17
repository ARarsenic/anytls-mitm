package mitm

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
)

// inspectionReader observes a bounded prefix of bytes already read for relay.
// It never reads ahead: fragmented authentication and server-first protocols
// must not wait for inspection before either direction can make progress.
type inspectionReader struct {
	source io.Reader
	prefix []byte
	done   bool
	report func(bool, []byte, *AnyTLSMetadata)
}

func (r *inspectionReader) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	if !r.done {
		keep := min(n, MaxInspectBufferSize-len(r.prefix))
		r.prefix = append(r.prefix, p[:keep]...)
		r.inspect(err != nil)
	}
	return n, err
}

func (r *inspectionReader) inspect(final bool) {
	finish := func(matched bool, hash []byte, meta *AnyTLSMetadata) {
		r.done = true
		r.prefix = nil
		r.report(matched, hash, meta)
	}
	for _, prefix := range httpPrefixes {
		if bytes.HasPrefix(r.prefix, prefix) {
			finish(false, nil, nil)
			return
		}
	}
	if len(r.prefix) >= MinFirstPacketHeaderLen {
		offset := MinFirstPacketHeaderLen + int(binary.BigEndian.Uint16(r.prefix[32:34]))
		needed := offset + 7
		if needed > MaxInspectBufferSize {
			finish(false, nil, nil)
			return
		}
		if len(r.prefix) >= needed {
			// Wait for optional metadata in our local prefix, never on the socket.
			if r.prefix[offset] == CmdSettings && binary.BigEndian.Uint32(r.prefix[offset+1:offset+5]) == 0 {
				size := needed + int(binary.BigEndian.Uint16(r.prefix[offset+5:offset+7]))
				if size <= MaxInspectBufferSize && len(r.prefix) < size && !final {
					return
				}
			}
			matched, hash, meta, _ := InspectAnyTLS(bufio.NewReaderSize(bytes.NewReader(r.prefix), MaxInspectBufferSize))
			finish(matched, hash, meta)
			return
		}
	}
	if final || len(r.prefix) == MaxInspectBufferSize {
		finish(false, nil, nil)
	}
}
