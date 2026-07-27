package padding

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestClassifierByteLevelMatrixRoundTrip(t *testing.T) {
	type packetCase struct {
		name       string
		packet     []byte
		wantPadded bool
	}

	cases := []packetCase{
		{name: "small_ipv4_icmp", packet: ipv4Packet(1, 96, 0, 0, 0), wantPadded: true},
		{name: "mid_ipv4_icmp", packet: ipv4Packet(1, 300, 0, 0, 0), wantPadded: false},
		{name: "big_ipv4_icmp", packet: ipv4Packet(1, OptimalPaddedSize, 0, 0, 0), wantPadded: false},
		{name: "small_ipv4_tcp_syn", packet: ipv4Packet(6, 96, 0x02, 0, 0), wantPadded: true},
		{name: "mid_ipv4_tcp_syn", packet: ipv4Packet(6, 300, 0x02, 0, 0), wantPadded: false},
		{name: "big_ipv4_tcp_syn", packet: ipv4Packet(6, OptimalPaddedSize, 0x02, 0, 0), wantPadded: false},
		{name: "small_ipv4_tcp_data", packet: ipv4Packet(6, 96, 0x10, 0, 0), wantPadded: true},
		{name: "mid_ipv4_tcp_data", packet: ipv4Packet(6, 300, 0x10, 0, 0), wantPadded: false},
		{name: "big_ipv4_tcp_data", packet: ipv4Packet(6, OptimalPaddedSize, 0x10, 0, 0), wantPadded: false},
		{name: "small_ipv4_udp_dns", packet: ipv4Packet(17, 96, 0, 44000, 53), wantPadded: true},
		{name: "mid_ipv4_udp_dns", packet: ipv4Packet(17, 300, 0, 53, 44000), wantPadded: true},
		{name: "big_ipv4_udp_dns", packet: ipv4Packet(17, OptimalPaddedSize, 0, 53, 44000), wantPadded: false},
		{name: "small_ipv4_udp_generic", packet: ipv4Packet(17, 96, 0, 44000, 44001), wantPadded: true},
		{name: "mid_ipv4_udp_generic", packet: ipv4Packet(17, 300, 0, 44000, 44001), wantPadded: false},
		{name: "big_ipv4_udp_generic", packet: ipv4Packet(17, OptimalPaddedSize, 0, 44000, 44001), wantPadded: false},
		{name: "small_ipv6_icmpv6", packet: ipv6Packet(58, 96), wantPadded: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			classifier := NewClassifier(true)
			padded, gotLen, gotPadded := classifier.ClassifyAndPad(tc.packet, len(tc.packet))
			if gotPadded != tc.wantPadded {
				t.Fatalf("wasPadded=%v want %v", gotPadded, tc.wantPadded)
			}
			if !tc.wantPadded {
				if gotLen != len(tc.packet) || !bytes.Equal(padded[:gotLen], tc.packet) {
					t.Fatalf("unexpected passthrough result len=%d input=%d", gotLen, len(tc.packet))
				}
				return
			}

			if gotLen != OptimalPaddedSize || len(padded) != OptimalPaddedSize {
				t.Fatalf("padded length=%d slice=%d want %d", gotLen, len(padded), OptimalPaddedSize)
			}
			if !bytes.Equal(padded[:len(tc.packet)], tc.packet) {
				t.Fatalf("padded prefix does not preserve packet bytes")
			}
			if stored := int(binary.BigEndian.Uint16(padded[len(tc.packet) : len(tc.packet)+2])); stored != len(tc.packet) {
				t.Fatalf("stored original length=%d want %d", stored, len(tc.packet))
			}
			if marker := padded[len(tc.packet)+2]; marker != PaddingMarker {
				t.Fatalf("padding marker=%#x want %#x", marker, PaddingMarker)
			}

			unpadded, unpaddedLen := classifier.Unpad(padded)
			if unpaddedLen != len(tc.packet) {
				t.Fatalf("unpadded length=%d want %d", unpaddedLen, len(tc.packet))
			}
			if !bytes.Equal(unpadded[:unpaddedLen], tc.packet) {
				t.Fatalf("unpadded bytes do not match original packet")
			}
		})
	}
}

func TestClassifierRejectsMalformedPaddingBytes(t *testing.T) {
	classifier := NewClassifier(true)
	packet := ipv4Packet(1, 96, 0, 0, 0)
	padded, _, wasPadded := classifier.ClassifyAndPad(packet, len(packet))
	if !wasPadded {
		t.Fatal("expected packet to be padded")
	}

	t.Run("bad_marker", func(t *testing.T) {
		tampered := append([]byte(nil), padded...)
		tampered[len(packet)+2] = 0x00
		_, n := classifier.Unpad(tampered)
		if n != OptimalPaddedSize {
			t.Fatalf("bad marker was accepted, unpadded length=%d", n)
		}
	})

	t.Run("bad_stored_length", func(t *testing.T) {
		tampered := append([]byte(nil), padded...)
		binary.BigEndian.PutUint16(tampered[len(packet):len(packet)+2], uint16(len(packet)+1))
		_, n := classifier.Unpad(tampered)
		if n != OptimalPaddedSize {
			t.Fatalf("bad stored length was accepted, unpadded length=%d", n)
		}
	})

	t.Run("ip_total_length_mismatch", func(t *testing.T) {
		malformed := append([]byte(nil), packet...)
		binary.BigEndian.PutUint16(malformed[2:4], uint16(len(packet)+1))
		out, n, wasPadded := classifier.ClassifyAndPad(malformed, len(malformed))
		if wasPadded || n != len(malformed) || !bytes.Equal(out[:n], malformed) {
			t.Fatalf("malformed total length was padded: wasPadded=%v len=%d", wasPadded, n)
		}
	})
}

func TestClassifierDisabledIsBytePassthrough(t *testing.T) {
	classifier := NewClassifier(false)
	packet := ipv4Packet(17, 96, 0, 53, 44000)
	out, n, wasPadded := classifier.ClassifyAndPad(packet, len(packet))
	if wasPadded || n != len(packet) || !bytes.Equal(out[:n], packet) {
		t.Fatalf("disabled classifier changed packet: wasPadded=%v len=%d", wasPadded, n)
	}
	unpadded, unpaddedLen := classifier.Unpad(out[:n])
	if unpaddedLen != len(packet) || !bytes.Equal(unpadded[:unpaddedLen], packet) {
		t.Fatalf("disabled classifier unpad changed packet")
	}
}

func TestClassifierDoesNotPadWhenMarkerWouldOverflow(t *testing.T) {
	classifier := NewClassifier(true)

	for _, totalLen := range []int{OptimalPaddedSize - 2, OptimalPaddedSize - 1} {
		t.Run(fmt.Sprintf("dns_len_%d", totalLen), func(t *testing.T) {
			packet := ipv4Packet(17, totalLen, 0, 53, 44000)
			out, gotLen, wasPadded := classifier.ClassifyAndPad(packet, len(packet))
			if wasPadded {
				t.Fatalf("packet length %d was padded despite no marker room", totalLen)
			}
			if gotLen != len(packet) || !bytes.Equal(out[:len(packet)], packet) {
				t.Fatalf("boundary packet was not passed through unchanged: gotLen=%d", gotLen)
			}
		})
	}
}

func TestClassifierRejectsInvalidReadLengthWithoutPanic(t *testing.T) {
	classifier := NewClassifier(true)

	cases := []struct {
		name string
		buf  []byte
		n    int
	}{
		{name: "empty", buf: nil, n: 0},
		{name: "negative", buf: []byte{0x45}, n: -1},
		{name: "beyond_buffer", buf: []byte{0x45, 0x00}, n: 20},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, gotLen, wasPadded := classifier.ClassifyAndPad(tc.buf, tc.n)
			if wasPadded {
				t.Fatalf("invalid length was padded")
			}
			if gotLen < 0 || gotLen > len(out) {
				t.Fatalf("unsafe returned length=%d for output slice length=%d", gotLen, len(out))
			}
		})
	}
}

func TestClassifierDisabledNormalizesInvalidReadLength(t *testing.T) {
	classifier := NewClassifier(false)
	out, n, wasPadded := classifier.ClassifyAndPad([]byte{0x45}, 20)
	if wasPadded {
		t.Fatal("disabled classifier should not pad")
	}
	if n != len(out) {
		t.Fatalf("disabled classifier returned unsafe length=%d for output len=%d", n, len(out))
	}
}

func ipv4Packet(protocol byte, totalLen int, tcpFlags byte, srcPort int, dstPort int) []byte {
	if totalLen < 60 {
		totalLen = 60
	}
	packet := make([]byte, totalLen)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	packet[9] = protocol
	switch protocol {
	case 6:
		packet[20+13] = tcpFlags
	case 17:
		binary.BigEndian.PutUint16(packet[20:22], uint16(srcPort))
		binary.BigEndian.PutUint16(packet[22:24], uint16(dstPort))
	}
	return packet
}

func ipv6Packet(nextHeader byte, totalLen int) []byte {
	if totalLen < 60 {
		totalLen = 60
	}
	packet := make([]byte, totalLen)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(totalLen-40))
	packet[6] = nextHeader
	return packet
}
