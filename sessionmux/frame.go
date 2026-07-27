// Package sessionmux multiplexes logical weaverssh services over one already
// authenticated bidirectional stream. It does not create listeners or allocate
// transport ports; callers supply the SSH X11-derived WebSocket stream.
package sessionmux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Version 2 activates mandatory per-stream WINDOW credit. Version 1 peers
	// ignored WINDOW and therefore cannot safely interoperate with bounded streams.
	protocolVersion   uint8 = 2
	headerSize              = 20
	defaultMaxPayload       = 16 << 20
)

var frameMagic = [4]byte{'W', 'V', 'M', '1'}

// FrameType identifies a session-multiplexer protocol action.
type FrameType uint8

const (
	FrameOpen FrameType = iota + 1
	FrameAccept
	FrameData
	FrameWindow
	FrameClose
	FrameReset
	FramePing
	FramePong
)

func (t FrameType) valid() bool {
	return t >= FrameOpen && t <= FramePong
}

// ServiceID identifies the logical service carried by a stream.
type ServiceID uint16

const (
	ServiceControl ServiceID = iota + 1
	ServiceFS
	ServiceTCP
	ServiceExec
	ServiceEvents
	// ServiceUDP carries one framed RFC 1928 UDP association. It is appended so
	// all existing service wire numbers remain stable.
	ServiceUDP
)

// Valid reports whether s is a protocol-defined service.
func (s ServiceID) Valid() bool {
	return s >= ServiceControl && s <= ServiceUDP
}

// String returns the stable wire/debug name for a service.
func (s ServiceID) String() string {
	switch s {
	case ServiceControl:
		return "control"
	case ServiceFS:
		return "fs"
	case ServiceTCP:
		return "tcp"
	case ServiceExec:
		return "exec"
	case ServiceEvents:
		return "events"
	case ServiceUDP:
		return "udp"
	default:
		return fmt.Sprintf("service(%d)", uint16(s))
	}
}

// Frame is one wire-level multiplexer message.
type Frame struct {
	Type     FrameType
	Flags    uint16
	StreamID uint32
	Service  ServiceID
	Payload  []byte
}

// Codec reads and writes bounded session-multiplexer frames.
type Codec struct {
	MaxPayload uint32
}

func (c Codec) maxPayload() uint32 {
	if c.MaxPayload == 0 {
		return defaultMaxPayload
	}
	return c.MaxPayload
}

// WriteFrame serializes one frame to w.
func (c Codec) WriteFrame(w io.Writer, frame Frame) error {
	if !frame.Type.valid() {
		return fmt.Errorf("sessionmux: invalid frame type %d", frame.Type)
	}
	if uint64(len(frame.Payload)) > uint64(c.maxPayload()) {
		return fmt.Errorf("sessionmux: payload too large: %d > %d", len(frame.Payload), c.maxPayload())
	}
	if err := validateFramePayloadLength(frame.Type, uint32(len(frame.Payload))); err != nil {
		return err
	}
	if frame.StreamID == 0 && frame.Type != FramePing && frame.Type != FramePong {
		return errors.New("sessionmux: stream 0 is reserved for session control")
	}
	if frame.Type == FrameOpen && !frame.Service.Valid() {
		return fmt.Errorf("sessionmux: invalid service %d", frame.Service)
	}

	header := make([]byte, headerSize)
	copy(header[:4], frameMagic[:])
	header[4] = protocolVersion
	header[5] = byte(frame.Type)
	binary.BigEndian.PutUint16(header[6:8], frame.Flags)
	binary.BigEndian.PutUint32(header[8:12], frame.StreamID)
	binary.BigEndian.PutUint16(header[12:14], uint16(frame.Service))
	// bytes 14:16 are reserved for future protocol negotiation.
	binary.BigEndian.PutUint32(header[16:20], uint32(len(frame.Payload)))

	if err := writeFull(w, header); err != nil {
		return err
	}
	return writeFull(w, frame.Payload)
}

// ReadFrame decodes one frame from r.
func (c Codec) ReadFrame(r io.Reader) (Frame, error) {
	header := make([]byte, headerSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	if string(header[:4]) != string(frameMagic[:]) {
		return Frame{}, errors.New("sessionmux: invalid frame magic")
	}
	if header[4] != protocolVersion {
		return Frame{}, fmt.Errorf("sessionmux: unsupported protocol version %d", header[4])
	}

	frame := Frame{
		Type:     FrameType(header[5]),
		Flags:    binary.BigEndian.Uint16(header[6:8]),
		StreamID: binary.BigEndian.Uint32(header[8:12]),
		Service:  ServiceID(binary.BigEndian.Uint16(header[12:14])),
	}
	if !frame.Type.valid() {
		return Frame{}, fmt.Errorf("sessionmux: invalid frame type %d", frame.Type)
	}
	if frame.StreamID == 0 && frame.Type != FramePing && frame.Type != FramePong {
		return Frame{}, errors.New("sessionmux: stream 0 is reserved for session control")
	}
	length := binary.BigEndian.Uint32(header[16:20])
	if length > c.maxPayload() {
		return Frame{}, fmt.Errorf("sessionmux: payload too large: %d > %d", length, c.maxPayload())
	}
	// Fixed-shape control frames are validated before allocating payload memory.
	if err := validateFramePayloadLength(frame.Type, length); err != nil {
		return Frame{}, err
	}
	if length > 0 {
		frame.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, frame.Payload); err != nil {
			return Frame{}, err
		}
	}
	return frame, nil
}

func validateFramePayloadLength(frameType FrameType, length uint32) error {
	switch frameType {
	case FrameWindow:
		if length != 4 {
			return fmt.Errorf("%w: WINDOW payload length %d", ErrFlowControlViolation, length)
		}
	case FrameAccept, FrameClose, FrameReset:
		if length != 0 {
			return fmt.Errorf("sessionmux: %v frame must not carry payload", frameType)
		}
	}
	return nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
