package padding

import (
	"encoding/binary"
	"fmt"
)

const (
	// SSH X11 optimal packet size - triggers window updates efficiently
	OptimalPaddedSize = 768

	// Packets smaller than this get padded
	PaddingThreshold = 256

	// Padding marker after original data
	PaddingMarker = 0xFF
)

func safePacketLength(buf []byte, n int) (int, bool) {
	if n < 0 {
		return 0, false
	}
	if n > len(buf) {
		return len(buf), false
	}
	return n, true
}

// Classifier analyzes and pads packets for SSH X11 forwarding compatibility
type Classifier struct {
	enabled bool
	stats   Stats
}

// Stats tracks padding statistics
type Stats struct {
	ICMP     uint64
	DNS      uint64
	TCPCtrl  uint64 // SYN/FIN/RST
	TCPData  uint64
	UDPSmall uint64
	UDPLarge uint64
	Padded   uint64
}

// NewClassifier creates a new packet classifier
func NewClassifier(enabled bool) *Classifier {
	return &Classifier{
		enabled: enabled,
	}
}

// IsEnabled returns whether padding is enabled
func (c *Classifier) IsEnabled() bool {
	return c.enabled
}

// ClassifyAndPad analyzes a packet and optionally pads it
// Returns: (paddedData, length, wasPadded)
func (c *Classifier) ClassifyAndPad(buf []byte, n int) ([]byte, int, bool) {
	n, validLength := safePacketLength(buf, n)

	// If padding disabled, pass through unchanged
	if !c.enabled {
		return buf, n, false
	}

	if !validLength || n == 0 {
		return buf, n, false
	}

	// Don't pad packets already at optimal size, or packets that leave no
	// room for the stored length plus marker bytes.
	if n >= OptimalPaddedSize || n+2 >= OptimalPaddedSize {
		return buf, n, false
	}

	ipVersion := buf[0] >> 4
	var packetTotalLen int
	var protocol byte

	if ipVersion == 4 {
		if n < 20 {
			return buf, n, false
		}
		packetTotalLen = int(buf[2])<<8 | int(buf[3])
		protocol = buf[9]
	} else if ipVersion == 6 {
		if n < 40 {
			return buf, n, false
		}
		payloadLen := int(buf[4])<<8 | int(buf[5])
		packetTotalLen = 40 + payloadLen
		protocol = buf[6] // Next Header
	} else {
		return buf, n, false
	}

	// Sanity check: calculated length should match what we read
	if packetTotalLen != n {
		return buf, n, false
	}

	needsPadding := false

	switch protocol {
	case 1: // ICMP
		c.stats.ICMP++
		needsPadding = packetTotalLen < PaddingThreshold

	case 58: // ICMPv6
		c.stats.ICMP++
		needsPadding = packetTotalLen < PaddingThreshold

	case 6: // TCP
		tcpOffset := 20
		if ipVersion == 6 {
			tcpOffset = 40
		}
		if n >= tcpOffset+14 {
			tcpFlags := buf[tcpOffset+13]
			isSYN := (tcpFlags & 0x02) != 0
			isFIN := (tcpFlags & 0x01) != 0
			isRST := (tcpFlags & 0x04) != 0

			if isSYN || isFIN || isRST {
				c.stats.TCPCtrl++
				needsPadding = n < PaddingThreshold
			} else {
				c.stats.TCPData++
				needsPadding = n < PaddingThreshold
			}
		}

	case 17: // UDP
		udpOffset := 20
		if ipVersion == 6 {
			udpOffset = 40
		}
		if n >= udpOffset+8 {
			srcPort := int(buf[udpOffset])<<8 | int(buf[udpOffset+1])
			dstPort := int(buf[udpOffset+2])<<8 | int(buf[udpOffset+3])

			if srcPort == 53 || dstPort == 53 {
				c.stats.DNS++
				needsPadding = true
			} else if n < PaddingThreshold {
				c.stats.UDPSmall++
				needsPadding = true
			} else {
				c.stats.UDPLarge++
			}
		}
	}

	if !needsPadding {
		return buf, n, false
	}

	// Pad to optimal size
	c.stats.Padded++
	padded := make([]byte, OptimalPaddedSize)
	copy(padded, buf[:n])
	binary.BigEndian.PutUint16(padded[n:], uint16(n))
	padded[n+2] = PaddingMarker

	return padded, OptimalPaddedSize, true
}

// Unpad removes padding from a packet
// Returns: (data, actualLength)
func (c *Classifier) Unpad(data []byte) ([]byte, int) {
	n := len(data)

	// If padding disabled, pass through unchanged
	if !c.enabled {
		return data, n
	}

	if n != OptimalPaddedSize || n < 20 {
		return data, n
	}

	ipVersion := data[0] >> 4
	var packetTotalLen int

	if ipVersion == 4 {
		if n < 20 {
			return data, n
		}
		packetTotalLen = int(data[2])<<8 | int(data[3])
	} else if ipVersion == 6 {
		if n < 40 {
			return data, n
		}
		payloadLen := int(data[4])<<8 | int(data[5])
		packetTotalLen = 40 + payloadLen
	} else {
		return data, n
	}

	minSize := 20
	if ipVersion == 6 {
		minSize = 40
	}

	// Check for padding marker
	if packetTotalLen >= minSize && packetTotalLen < OptimalPaddedSize-2 {
		if data[packetTotalLen+2] == PaddingMarker {
			storedSize := int(binary.BigEndian.Uint16(data[packetTotalLen : packetTotalLen+2]))
			if storedSize == packetTotalLen {
				return data, packetTotalLen
			}
		}
	}

	return data, n
}

// Stats returns padding statistics
func (c *Classifier) Stats() string {
	if !c.enabled {
		return "Padding disabled"
	}

	total := c.stats.ICMP + c.stats.DNS + c.stats.TCPCtrl +
		c.stats.TCPData + c.stats.UDPSmall + c.stats.UDPLarge

	if total == 0 {
		return "No packets processed"
	}

	return fmt.Sprintf(
		"Packets: %d total, %d padded (%.1f%%) - "+
			"ICMP:%d DNS:%d TCP-ctrl:%d TCP-data:%d UDP-sm:%d UDP-lg:%d",
		total, c.stats.Padded,
		float64(c.stats.Padded)*100/float64(total),
		c.stats.ICMP, c.stats.DNS, c.stats.TCPCtrl,
		c.stats.TCPData, c.stats.UDPSmall, c.stats.UDPLarge,
	)
}

// GetStats returns a copy of current statistics
func (c *Classifier) GetStats() Stats {
	return c.stats
}
