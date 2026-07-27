package sessionapi

import (
	"bufio"
	"errors"
	"io"
)

var ErrMessageTooLarge = errors.New("sessionapi: message too large")

func readMessage(reader io.Reader) ([]byte, error) {
	limited := io.LimitReader(reader, MaxMessageBytes+2)
	buffered := bufio.NewReaderSize(limited, MaxMessageBytes+2)
	payload, err := buffered.ReadBytes('\n')
	if len(payload) > MaxMessageBytes+1 {
		return nil, ErrMessageTooLarge
	}
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		return nil, io.ErrUnexpectedEOF
	}
	payload = payload[:len(payload)-1]
	if len(payload) == 0 || len(payload) > MaxMessageBytes {
		return nil, ErrMessageTooLarge
	}
	return payload, nil
}

func writeMessage(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > MaxMessageBytes {
		return ErrMessageTooLarge
	}
	framed := make([]byte, len(payload)+1)
	copy(framed, payload)
	framed[len(payload)] = '\n'
	return writeFull(writer, framed)
}
