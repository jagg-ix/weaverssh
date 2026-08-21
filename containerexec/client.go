package containerexec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// CallStream runs one non-interactive container action. stdin/stdout/stderr are
// streamed incrementally; no output is buffered into the response.
func CallStream(ctx context.Context, stream io.ReadWriteCloser, request Request, stdin io.Reader, stdout, stderr io.Writer) (Exit, error) {
	if stream == nil {
		return Exit{}, errors.New("containerexec: nil stream")
	}
	defer stream.Close()
	request.Protocol = ProtocolVersion
	if err := request.validate(); err != nil {
		return Exit{}, err
	}
	codec := Codec{}
	payload, _ := json.Marshal(request)
	if err := codec.WriteFrame(stream, Frame{Type: FrameStart, Payload: payload}); err != nil {
		return Exit{}, err
	}
	first, err := codec.ReadFrame(stream)
	if err != nil {
		return Exit{}, err
	}
	if first.Type == FrameError {
		return Exit{}, decodeResponseError(first.Payload)
	}
	if first.Type != FrameReady {
		return Exit{}, errors.New("containerexec: expected READY")
	}
	var ready Ready
	if err := decodeStrict(first.Payload, &ready); err != nil || ready.Protocol != ProtocolVersion || strings.TrimSpace(ready.SessionID) == "" || strings.TrimSpace(ready.Provider) == "" {
		return Exit{}, errors.New("containerexec: invalid READY")
	}

	inputErr := make(chan error, 1)
	go func() {
		finish := func(err error) {
			inputErr <- err
			if err != nil {
				_ = stream.Close()
			}
		}
		if stdin != nil && ready.Capabilities.Stdin {
			buffer := make([]byte, outputChunkBytes)
			for {
				count, readErr := stdin.Read(buffer)
				if count > 0 {
					if writeErr := codec.WriteFrame(stream, Frame{Type: FrameStdin, Payload: append([]byte(nil), buffer[:count]...)}); writeErr != nil {
						finish(writeErr)
						return
					}
				}
				if readErr != nil {
					if errors.Is(readErr, io.EOF) {
						finish(codec.WriteFrame(stream, Frame{Type: FrameCloseStdin}))
					} else {
						finish(readErr)
					}
					return
				}
			}
		}
		finish(codec.WriteFrame(stream, Frame{Type: FrameCloseStdin}))
	}()

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
		case <-done:
		}
	}()
	defer close(done)
	for {
		frame, readErr := codec.ReadFrame(stream)
		if readErr != nil {
			select {
			case writeErr := <-inputErr:
				if writeErr != nil {
					return Exit{}, writeErr
				}
			default:
			}
			return Exit{}, readErr
		}
		switch frame.Type {
		case FrameStdout:
			if stdout != nil {
				if _, err := stdout.Write(frame.Payload); err != nil {
					return Exit{}, err
				}
			}
		case FrameStderr:
			if stderr != nil {
				if _, err := stderr.Write(frame.Payload); err != nil {
					return Exit{}, err
				}
			}
		case FrameExit:
			var exit Exit
			if err := decodeStrict(frame.Payload, &exit); err != nil || exit.Protocol != ProtocolVersion {
				return Exit{}, errors.New("containerexec: invalid EXIT")
			}
			return exit, nil
		case FrameError:
			return Exit{}, decodeResponseError(frame.Payload)
		default:
			return Exit{}, errors.New("containerexec: unexpected server frame")
		}
	}
}

func decodeResponseError(payload []byte) error {
	var response ResponseError
	if err := decodeStrict(payload, &response); err != nil || response.Protocol != ProtocolVersion {
		return errors.New("containerexec: invalid ERROR")
	}
	return fmt.Errorf("containerexec %s: %s", response.Code, response.Message)
}
