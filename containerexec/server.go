package containerexec

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"weaverssh/containerstream"
)

type Server struct {
	Manager *containerstream.ProcessManager
	// ProcessFS is the optional file-shaped facade over Manager. The routed
	// Exec protocol remains primary; the typed ServiceFS attach uses this exact
	// facade rather than allocating a second process registry.
	ProcessFS        *containerstream.ProcessFS
	Codec            Codec
	ResolvePrincipal func(OpenMetadata) (string, error)
	DrainTimeout     time.Duration
}

func (s *Server) ServeBound(ctx context.Context, stream io.ReadWriteCloser, rawMetadata []byte) error {
	if s == nil || s.Manager == nil || stream == nil {
		return errors.New("containerexec: incomplete server")
	}
	defer stream.Close()
	metadata, err := ParseOpenMetadata(rawMetadata)
	if err != nil {
		return err
	}
	if metadata.SourceNode == "" || metadata.SourceBinding == "" || !validLowerSHA256(metadata.ChainSHA256) {
		return errors.New("containerexec: metadata was not bound by the broker")
	}
	principal := metadata.SourceNode
	if s.ResolvePrincipal != nil {
		principal, err = s.ResolvePrincipal(metadata)
		if err != nil {
			return err
		}
	}
	first, err := s.Codec.ReadFrame(stream)
	if err != nil {
		return err
	}
	if first.Type != FrameStart {
		_ = s.writeError(stream, "protocol", "first frame must be START")
		return errors.New("containerexec: first frame must be START")
	}
	var request Request
	if err := decodeStrict(first.Payload, &request); err != nil || request.validate() != nil {
		_ = s.writeError(stream, "invalid_request", "invalid container exec request")
		return errors.New("containerexec: invalid request")
	}
	target, _ := containerstream.ParseURI(request.TargetURI)
	if target.Endpoint != metadata.TargetNode {
		_ = s.writeError(stream, "denied", "container target is not on the routed node")
		return errors.New("containerexec: target node mismatch")
	}
	session, err := s.Manager.CreateSession(containerstream.ProcessIdentity{
		Principal: principal, SourceNode: metadata.SourceNode,
		SourceBinding: metadata.SourceBinding, ChainSHA256: metadata.ChainSHA256,
	}, target)
	if err != nil {
		_ = s.writeError(stream, "unavailable", "container process session unavailable")
		return err
	}
	defer s.Manager.RemoveSession(session)
	if err := session.Start(ctx, containerstream.StartRequest{Action: request.Action, Args: request.Args}); err != nil {
		_ = s.writeError(stream, errorCode(err), "container process start denied or failed")
		return err
	}
	status := session.Status()
	var stdin io.WriteCloser
	if status.Capabilities.Stdin {
		stdin, err = session.OpenStdin()
		if err != nil {
			return err
		}
	}
	var stdout, stderr io.ReadCloser
	if status.Capabilities.Stdout {
		stdout, err = session.Stdout()
		if err != nil {
			return err
		}
	}
	if status.Capabilities.Stderr {
		stderr, err = session.Stderr()
		if err != nil {
			return err
		}
	}
	writer := &lockedWriter{writer: stream, codec: s.Codec}
	ready, _ := json.Marshal(Ready{Protocol: ProtocolVersion, SessionID: session.ID(), Provider: status.Provider, Capabilities: status.Capabilities})
	if err := writer.write(Frame{Type: FrameReady, Payload: ready}); err != nil {
		return err
	}
	clientErrors := make(chan error, 1)
	go func() { clientErrors <- s.readClient(ctx, stream, session, stdin) }()

	pumps := make([]<-chan error, 0, 2)
	if stdout != nil {
		pumps = append(pumps, pumpOutput(writer, FrameStdout, stdout))
	}
	if stderr != nil {
		pumps = append(pumps, pumpOutput(writer, FrameStderr, stderr))
	}
	waitResult := make(chan struct {
		status containerstream.ProcessStatus
		err    error
	}, 1)
	go func() {
		terminal, waitErr := session.Wait(ctx)
		waitResult <- struct {
			status containerstream.ProcessStatus
			err    error
		}{terminal, waitErr}
	}()

	var terminal containerstream.ProcessStatus
	select {
	case result := <-waitResult:
		if result.err != nil {
			return result.err
		}
		terminal = result.status
	case readErr := <-clientErrors:
		if normalStreamEnd(readErr) {
			return nil
		}
		return readErr
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := waitOutputPumps(ctx, s.DrainTimeout, pumps); err != nil {
		return err
	}
	exitCode := -1
	if terminal.ExitCode != nil {
		exitCode = *terminal.ExitCode
	}
	payload, _ := json.Marshal(Exit{Protocol: ProtocolVersion, ExitCode: exitCode, Error: terminal.Error})
	return writer.write(Frame{Type: FrameExit, Payload: payload})
}

func (s *Server) readClient(ctx context.Context, reader io.Reader, session *containerstream.ProcessSession, stdin io.WriteCloser) error {
	for {
		frame, err := s.Codec.ReadFrame(reader)
		if err != nil {
			return err
		}
		switch frame.Type {
		case FrameStdin:
			if stdin == nil {
				return errors.New("containerexec: stdin unsupported")
			}
			if _, err := stdin.Write(frame.Payload); err != nil {
				return err
			}
		case FrameCloseStdin:
			if len(frame.Payload) != 0 {
				return errors.New("containerexec: CLOSE_STDIN payload must be empty")
			}
			if stdin != nil {
				if err := stdin.Close(); err != nil {
					return err
				}
				stdin = nil
			}
		case FrameSignal:
			if err := session.Signal(ctx, containerstream.ProcessSignal(strings.ToUpper(strings.TrimSpace(string(frame.Payload))))); err != nil {
				return err
			}
		default:
			return errors.New("containerexec: unexpected client frame")
		}
	}
}

func (s *Server) writeError(writer io.Writer, code, message string) error {
	payload, _ := json.Marshal(ResponseError{Protocol: ProtocolVersion, Code: code, Message: message})
	return s.Codec.WriteFrame(writer, Frame{Type: FrameError, Payload: payload})
}

type lockedWriter struct {
	mu     sync.Mutex
	writer io.Writer
	codec  Codec
}

func (w *lockedWriter) write(frame Frame) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.codec.WriteFrame(w.writer, frame)
}

func pumpOutput(writer *lockedWriter, frameType FrameType, reader io.ReadCloser) <-chan error {
	done := make(chan error, 1)
	go func() {
		defer reader.Close()
		buffer := make([]byte, outputChunkBytes)
		for {
			count, err := reader.Read(buffer)
			if count > 0 {
				if writeErr := writer.write(Frame{Type: frameType, Payload: append([]byte(nil), buffer[:count]...)}); writeErr != nil {
					done <- writeErr
					return
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
					done <- nil
				} else {
					done <- err
				}
				return
			}
		}
	}()
	return done
}

func waitOutputPumps(ctx context.Context, timeout time.Duration, pumps []<-chan error) error {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	drainCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for _, pump := range pumps {
		select {
		case err := <-pump:
			if err != nil {
				return err
			}
		case <-drainCtx.Done():
			return drainCtx.Err()
		}
	}
	return nil
}

func normalStreamEnd(err error) bool {
	return err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, context.Canceled)
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, containerstream.ErrProcessLimit):
		return "limit_exceeded"
	case errors.Is(err, containerstream.ErrProcessPermission):
		return "denied"
	default:
		return "unavailable"
	}
}
