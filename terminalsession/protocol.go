// Package terminalsession implements stateful, reconnectable PTY sessions over
// an already authenticated WeaverSSH multiplexed stream.
package terminalsession

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	ProtocolVersion = "weaverssh.terminal.v1"
	wireVersion     = uint8(1)
	wireHeaderSize  = 20
	DefaultMaxFrame = 1 << 20
)

var wireMagic = [4]byte{'W', 'V', 'T', '1'}

// FrameType identifies a terminal-session control or data action.
type FrameType uint8

const (
	FrameOpen FrameType = iota + 1
	FrameReady
	FrameError
	FrameInput
	FrameOutput
	FrameResize
	FrameDetach
	FrameTerminate
	FramePing
	FramePong
	// FrameExit is emitted by the agent immediately before an active process
	// session becomes terminal. It is appended to preserve existing wire IDs.
	FrameExit
)

const (
	FlagReplay uint16 = 1 << iota
	FlagTruncated
)

func (t FrameType) valid() bool { return t >= FrameOpen && t <= FrameExit }

// Frame is one terminal-session message. Sequence is non-zero on output
// frames and lets reconnecting clients discard duplicate replay safely.
type Frame struct {
	Type     FrameType
	Flags    uint16
	Sequence uint64
	Payload  []byte
}

// Codec reads and writes bounded terminal-session frames.
type Codec struct{ MaxPayload uint32 }

func (c Codec) maxPayload() uint32 {
	if c.MaxPayload == 0 {
		return DefaultMaxFrame
	}
	return c.MaxPayload
}

func (c Codec) WriteFrame(w io.Writer, frame Frame) error {
	if !frame.Type.valid() {
		return fmt.Errorf("terminalsession: invalid frame type %d", frame.Type)
	}
	if uint64(len(frame.Payload)) > uint64(c.maxPayload()) {
		return fmt.Errorf("terminalsession: payload too large: %d > %d", len(frame.Payload), c.maxPayload())
	}
	if err := validateFrameShape(frame); err != nil {
		return err
	}
	header := make([]byte, wireHeaderSize)
	copy(header[:4], wireMagic[:])
	header[4] = wireVersion
	header[5] = byte(frame.Type)
	binary.BigEndian.PutUint16(header[6:8], frame.Flags)
	binary.BigEndian.PutUint64(header[8:16], frame.Sequence)
	binary.BigEndian.PutUint32(header[16:20], uint32(len(frame.Payload)))
	if err := writeFull(w, header); err != nil {
		return err
	}
	return writeFull(w, frame.Payload)
}

func (c Codec) ReadFrame(r io.Reader) (Frame, error) {
	header := make([]byte, wireHeaderSize)
	if _, err := io.ReadFull(r, header); err != nil {
		return Frame{}, err
	}
	if string(header[:4]) != string(wireMagic[:]) {
		return Frame{}, errors.New("terminalsession: invalid frame magic")
	}
	if header[4] != wireVersion {
		return Frame{}, fmt.Errorf("terminalsession: unsupported wire version %d", header[4])
	}
	frame := Frame{
		Type:     FrameType(header[5]),
		Flags:    binary.BigEndian.Uint16(header[6:8]),
		Sequence: binary.BigEndian.Uint64(header[8:16]),
	}
	if !frame.Type.valid() {
		return Frame{}, fmt.Errorf("terminalsession: invalid frame type %d", frame.Type)
	}
	length := binary.BigEndian.Uint32(header[16:20])
	if length > c.maxPayload() {
		return Frame{}, fmt.Errorf("terminalsession: payload too large: %d > %d", length, c.maxPayload())
	}
	if length > 0 {
		frame.Payload = make([]byte, length)
		if _, err := io.ReadFull(r, frame.Payload); err != nil {
			return Frame{}, err
		}
	}
	if err := validateFrameShape(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

func validateFrameShape(frame Frame) error {
	if frame.Flags & ^uint16(FlagReplay|FlagTruncated) != 0 {
		return errors.New("terminalsession: unknown frame flags")
	}
	if frame.Type == FrameOutput {
		if frame.Sequence == 0 || len(frame.Payload) == 0 {
			return errors.New("terminalsession: output requires a sequence and payload")
		}
		if frame.Flags&FlagTruncated != 0 && frame.Flags&FlagReplay == 0 {
			return errors.New("terminalsession: truncation is valid only during replay")
		}
		return nil
	}
	if frame.Sequence != 0 || frame.Flags != 0 {
		return errors.New("terminalsession: sequence and flags are reserved for output frames")
	}
	switch frame.Type {
	case FrameResize:
		if len(frame.Payload) != 4 {
			return errors.New("terminalsession: resize payload must be four bytes")
		}
	case FrameDetach, FrameTerminate, FramePing, FramePong:
		if len(frame.Payload) != 0 {
			return errors.New("terminalsession: control frame must not carry payload")
		}
	case FrameExit:
		if len(frame.Payload) == 0 {
			return errors.New("terminalsession: exit frame requires a payload")
		}
	}
	return nil
}

func encodeSize(size TerminalSize) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint16(payload[:2], size.Rows)
	binary.BigEndian.PutUint16(payload[2:], size.Cols)
	return payload
}

func decodeSize(payload []byte) (TerminalSize, error) {
	if len(payload) != 4 {
		return TerminalSize{}, errors.New("terminalsession: resize payload must be four bytes")
	}
	size := TerminalSize{Rows: binary.BigEndian.Uint16(payload[:2]), Cols: binary.BigEndian.Uint16(payload[2:])}
	if err := size.Validate(); err != nil {
		return TerminalSize{}, err
	}
	return size, nil
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
