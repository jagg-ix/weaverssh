package app

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"
)

func TestX11ConnectionSetupParsesByteOrderAuthAndPadding(t *testing.T) {
	cookie, err := hex.DecodeString("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatalf("decode cookie: %v", err)
	}

	cases := []struct {
		name   string
		marker byte
		order  binary.ByteOrder
	}{
		{name: "little_endian", marker: LittleEndian, order: binary.LittleEndian},
		{name: "big_endian", marker: BigEndian, order: binary.BigEndian},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := buildX11SetupBytes(tc.marker, tc.order, cookie)
			setup, err := ReadConnectionSetup(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("ReadConnectionSetup: %v", err)
			}
			if setup.ByteOrder != tc.marker {
				t.Fatalf("byte order=%#x want %#x", setup.ByteOrder, tc.marker)
			}
			if setup.ProtocolMajorVer != ProtocolMajorVersion || setup.ProtocolMinorVer != ProtocolMinorVersion {
				t.Fatalf("protocol=%d.%d want %d.%d", setup.ProtocolMajorVer, setup.ProtocolMinorVer, ProtocolMajorVersion, ProtocolMinorVersion)
			}
			if setup.AuthProtoName != AuthProtoMITMagicCookie {
				t.Fatalf("auth proto=%q want %q", setup.AuthProtoName, AuthProtoMITMagicCookie)
			}
			if !bytes.Equal(setup.AuthProtoData, cookie) {
				t.Fatalf("auth data=%x want %x", setup.AuthProtoData, cookie)
			}
		})
	}
}

func TestX11ConnectionSetupRejectsInvalidByteOrder(t *testing.T) {
	raw := buildX11SetupBytes(0x00, binary.LittleEndian, []byte{1, 2, 3, 4})
	if _, err := ReadConnectionSetup(bytes.NewReader(raw)); err == nil {
		t.Fatal("invalid byte order was accepted")
	}
}

func TestX11ConnectionReplyLengthFieldMatchesBodyBytes(t *testing.T) {
	cases := []struct {
		name  string
		order binary.ByteOrder
	}{
		{name: "little_endian", order: binary.LittleEndian},
		{name: "big_endian", order: binary.BigEndian},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := NewX11Server("00112233445566778899aabbccddeeff")
			client := &ClientConnection{byteOrder: tc.order}
			reply := server.buildConnectionReply(true, client)
			var out bytes.Buffer
			if err := reply.Write(&out, tc.order); err != nil {
				t.Fatalf("write reply: %v", err)
			}
			raw := out.Bytes()
			if len(raw) < 8 {
				t.Fatalf("reply too short: %d", len(raw))
			}
			additionalLen := int(tc.order.Uint16(raw[6:8])) * 4
			if additionalLen != len(raw)-8 {
				t.Fatalf("additional length=%d want %d", additionalLen, len(raw)-8)
			}
		})
	}
}

func TestSecurityGenerateAuthValueMaskAndTimeoutBytes(t *testing.T) {
	cases := []struct {
		name  string
		order binary.ByteOrder
	}{
		{name: "little_endian", order: binary.LittleEndian},
		{name: "big_endian", order: binary.BigEndian},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := make([]byte, 16)
			tc.order.PutUint32(data[0:4], SecurityAuthTimeoutMask|SecurityAuthTrustLevelMask|SecurityAuthGroupMask)
			tc.order.PutUint32(data[4:8], 30)
			tc.order.PutUint32(data[8:12], TRUSTED_LEVEL)
			tc.order.PutUint32(data[12:16], 99)
			var req SecurityGenerateAuthRequest
			if err := req.Parse(data, tc.order); err != nil {
				t.Fatalf("parse generate auth: %v", err)
			}
			if req.Timeout != 30 || req.TrustLevel != TRUSTED_LEVEL || req.Group != 99 {
				t.Fatalf("parsed timeout=%d trust=%d group=%d", req.Timeout, req.TrustLevel, req.Group)
			}
		})
	}

	var truncated SecurityGenerateAuthRequest
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data, SecurityAuthTimeoutMask)
	if err := truncated.Parse(data, binary.LittleEndian); err != nil {
		t.Fatalf("parse truncated generate auth: %v", err)
	}
	if truncated.Timeout != 0 || truncated.TrustLevel != UNTRUSTED_LEVEL || truncated.Group != 0 {
		t.Fatalf("truncated values changed defaults: %+v", truncated)
	}
}

func TestX11ServerValidateAuthInitialGeneratedAndExpiredCookies(t *testing.T) {
	initialCookieHex := "00112233445566778899aabbccddeeff"
	initialCookie, _ := hex.DecodeString(initialCookieHex)
	generatedCookie, _ := hex.DecodeString("ffeeddccbbaa99887766554433221100")
	server := NewX11Server(initialCookieHex)
	client := &ClientConnection{byteOrder: binary.LittleEndian}

	if !server.validateAuth(&ConnectionSetup{AuthProtoName: AuthProtoMITMagicCookie, AuthProtoData: initialCookie}, client) {
		t.Fatal("initial MIT cookie was rejected")
	}

	server.authorizations[7] = &Authorization{
		ID:        7,
		Cookie:    generatedCookie,
		Timeout:   30,
		CreatedAt: time.Now(),
	}
	if !server.validateAuth(&ConnectionSetup{AuthProtoName: AuthProtoMITMagicCookie, AuthProtoData: generatedCookie}, client) {
		t.Fatal("valid generated MIT cookie was rejected")
	}

	server.authorizations[7].CreatedAt = time.Now().Add(-2 * time.Second)
	server.authorizations[7].Timeout = 1
	if server.validateAuth(&ConnectionSetup{AuthProtoName: AuthProtoMITMagicCookie, AuthProtoData: generatedCookie}, client) {
		t.Fatal("expired generated MIT cookie was accepted")
	}
}

func TestWebSocketReadFrameUnmasksAndDecodesExtendedLengths(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{name: "short", size: 5},
		{name: "extended_126", size: 126},
		{name: "extended_127", size: 66000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := repeatedPayload(tc.size)
			conn := newMemoryConn(maskedWebSocketFrame(OpcodeBinary, payload, [4]byte{0x10, 0x20, 0x30, 0x40}))
			mpc := NewMultiProtocolConnection(conn)
			mpc.protocol = ProtocolWebSocket

			frame, err := mpc.ReadWebSocketFrame()
			if err != nil {
				t.Fatalf("read websocket frame: %v", err)
			}
			if !frame.Fin || frame.Opcode != OpcodeBinary || !frame.Masked {
				t.Fatalf("unexpected frame metadata: fin=%v opcode=%d masked=%v", frame.Fin, frame.Opcode, frame.Masked)
			}
			if !bytes.Equal(frame.Payload, payload) {
				t.Fatalf("payload mismatch for size %d", tc.size)
			}
		})
	}
}

func TestWebSocketWriteFrameUsesUnmaskedServerLengthEncodings(t *testing.T) {
	cases := []struct {
		name string
		size int
	}{
		{name: "short_125", size: 125},
		{name: "extended_126", size: 126},
		{name: "extended_127", size: 65536},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := repeatedPayload(tc.size)
			conn := newMemoryConn(nil)
			mpc := NewMultiProtocolConnection(conn)
			mpc.protocol = ProtocolWebSocket
			if err := mpc.WriteWebSocketFrame(&WebSocketFrame{Fin: true, Opcode: OpcodeBinary, Payload: payload}); err != nil {
				t.Fatalf("write websocket frame: %v", err)
			}
			raw := conn.written.Bytes()
			if len(raw) < 2 {
				t.Fatalf("frame too short: %d", len(raw))
			}
			if raw[0] != 0x80|OpcodeBinary {
				t.Fatalf("first byte=%#x", raw[0])
			}
			if raw[1]&0x80 != 0 {
				t.Fatal("server frame unexpectedly set mask bit")
			}
			payloadOffset := assertWebSocketLengthEncoding(t, raw, tc.size)
			if !bytes.Equal(raw[payloadOffset:], payload) {
				t.Fatalf("written payload mismatch for size %d", tc.size)
			}
		})
	}
}

func buildX11SetupBytes(marker byte, order binary.ByteOrder, cookie []byte) []byte {
	authName := []byte(AuthProtoMITMagicCookie)
	namePad := (4 - (len(authName) % 4)) % 4
	dataPad := (4 - (len(cookie) % 4)) % 4
	raw := make([]byte, 12+len(authName)+namePad+len(cookie)+dataPad)
	raw[0] = marker
	order.PutUint16(raw[2:4], ProtocolMajorVersion)
	order.PutUint16(raw[4:6], ProtocolMinorVersion)
	order.PutUint16(raw[6:8], uint16(len(authName)))
	order.PutUint16(raw[8:10], uint16(len(cookie)))
	copy(raw[12:], authName)
	copy(raw[12+len(authName)+namePad:], cookie)
	return raw
}

func repeatedPayload(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	return payload
}

func maskedWebSocketFrame(opcode uint8, payload []byte, mask [4]byte) []byte {
	var frame []byte
	frame = append(frame, 0x80|opcode)
	size := len(payload)
	switch {
	case size < 126:
		frame = append(frame, 0x80|byte(size))
	case size < 65536:
		frame = append(frame, 0x80|126, byte(size>>8), byte(size))
	default:
		frame = append(frame, 0x80|127)
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(uint64(size)>>uint(i*8)))
		}
	}
	frame = append(frame, mask[:]...)
	for i, b := range payload {
		frame = append(frame, b^mask[i%4])
	}
	return frame
}

func assertWebSocketLengthEncoding(t *testing.T, raw []byte, size int) int {
	t.Helper()
	switch {
	case size < 126:
		if raw[1] != byte(size) {
			t.Fatalf("short length byte=%#x want %#x", raw[1], byte(size))
		}
		return 2
	case size < 65536:
		if raw[1] != 126 {
			t.Fatalf("extended-126 marker=%#x", raw[1])
		}
		if got := int(binary.BigEndian.Uint16(raw[2:4])); got != size {
			t.Fatalf("extended-126 length=%d want %d", got, size)
		}
		return 4
	default:
		if raw[1] != 127 {
			t.Fatalf("extended-127 marker=%#x", raw[1])
		}
		if got := int(binary.BigEndian.Uint64(raw[2:10])); got != size {
			t.Fatalf("extended-127 length=%d want %d", got, size)
		}
		return 10
	}
}

type memoryConn struct {
	reader  *bytes.Reader
	written bytes.Buffer
}

func newMemoryConn(input []byte) *memoryConn {
	return &memoryConn{reader: bytes.NewReader(input)}
}

func (c *memoryConn) Read(p []byte) (int, error) {
	if c.reader == nil {
		return 0, io.EOF
	}
	return c.reader.Read(p)
}

func (c *memoryConn) Write(p []byte) (int, error) {
	return c.written.Write(p)
}

func (c *memoryConn) Close() error { return nil }

func (c *memoryConn) LocalAddr() net.Addr { return testAddr("local") }

func (c *memoryConn) RemoteAddr() net.Addr { return testAddr("remote") }

func (c *memoryConn) SetDeadline(time.Time) error { return nil }

func (c *memoryConn) SetReadDeadline(time.Time) error { return nil }

func (c *memoryConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return string(a) }

func (a testAddr) String() string { return string(a) }
