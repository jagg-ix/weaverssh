package sessionmux

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestCodecRejectsPreWindowProtocolVersion(t *testing.T) {
	header := make([]byte, headerSize)
	copy(header[:4], frameMagic[:])
	header[4] = 1 // v1 ignored WINDOW and is not safe for bounded streams.
	header[5] = byte(FramePing)
	binary.BigEndian.PutUint32(header[8:12], 0)
	_, err := (Codec{}).ReadFrame(bytes.NewReader(header))
	if err == nil || !strings.Contains(err.Error(), "unsupported protocol version 1") {
		t.Fatalf("ReadFrame error=%v", err)
	}
}
