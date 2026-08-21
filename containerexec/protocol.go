package containerexec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"weaverssh/containerstream"
)

const (
	ProtocolVersion  = "weaverssh.container-exec.v1"
	MaxFramePayload  = 1 << 20
	outputChunkBytes = 32 << 10
)

type FrameType uint8

const (
	FrameStart FrameType = iota + 1
	FrameReady
	FrameStdin
	FrameCloseStdin
	FrameSignal
	FrameStdout
	FrameStderr
	FrameExit
	FrameError
)

type Frame struct {
	Type    FrameType
	Payload []byte
}

type Codec struct{ MaxPayload uint32 }

func (c Codec) maximum() uint32 {
	if c.MaxPayload == 0 {
		return MaxFramePayload
	}
	return c.MaxPayload
}

func (c Codec) WriteFrame(writer io.Writer, frame Frame) error {
	if frame.Type < FrameStart || frame.Type > FrameError || uint64(len(frame.Payload)) > uint64(c.maximum()) {
		return errors.New("containerexec: invalid frame")
	}
	header := [5]byte{byte(frame.Type)}
	binary.BigEndian.PutUint32(header[1:], uint32(len(frame.Payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, frame.Payload)
}

func (c Codec) ReadFrame(reader io.Reader) (Frame, error) {
	var header [5]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Frame{}, err
	}
	frameType := FrameType(header[0])
	size := binary.BigEndian.Uint32(header[1:])
	if frameType < FrameStart || frameType > FrameError || size > c.maximum() {
		return Frame{}, errors.New("containerexec: invalid frame")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Frame{}, err
	}
	return Frame{Type: frameType, Payload: payload}, nil
}

type Request struct {
	Protocol  string   `json:"protocol"`
	TargetURI string   `json:"target_uri"`
	Action    string   `json:"action"`
	Args      []string `json:"args,omitempty"`
}

func (r Request) validate() error {
	if r.Protocol != ProtocolVersion || strings.TrimSpace(r.TargetURI) == "" || strings.TrimSpace(r.Action) == "" {
		return errors.New("containerexec: invalid request")
	}
	if _, err := containerstream.ParseURI(r.TargetURI); err != nil {
		return fmt.Errorf("containerexec: invalid target: %w", err)
	}
	if len(r.Args) > containerstream.MaxProcessArgs {
		return errors.New("containerexec: too many arguments")
	}
	for _, argument := range r.Args {
		if len(argument) > containerstream.MaxProcessArgument || strings.ContainsAny(argument, "\x00\r\n") {
			return errors.New("containerexec: invalid argument")
		}
	}
	return nil
}

type Ready struct {
	Protocol     string                              `json:"protocol"`
	SessionID    string                              `json:"session_id"`
	Provider     string                              `json:"provider"`
	Capabilities containerstream.ProcessCapabilities `json:"capabilities"`
}

type Exit struct {
	Protocol string `json:"protocol"`
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

type ResponseError struct {
	Protocol string `json:"protocol"`
	Code     string `json:"code"`
	Message  string `json:"message"`
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
