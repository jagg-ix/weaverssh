package terminalsession

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
)

type Server struct {
	Manager          *Manager
	Codec            Codec
	ResolvePrincipal func(OpenMetadata) (string, error)
}

// ServeBound derives identity from broker-bound metadata before accepting any
// terminal request. A deployment may map that binding to an SSO principal with
// ResolvePrincipal; the untrusted OPEN payload can never select its identity.
func (s *Server) ServeBound(ctx context.Context, stream io.ReadWriteCloser, rawMetadata []byte) error {
	metadata, err := ParseOpenMetadata(rawMetadata)
	if err != nil {
		return err
	}
	if metadata.SourceNode == "" || metadata.SourceBinding == "" || len(metadata.ChainSHA256) != 64 {
		return errors.New("terminalsession: terminal metadata was not bound by the broker")
	}
	principal := metadata.SourceNode
	if s.ResolvePrincipal != nil {
		principal, err = s.ResolvePrincipal(metadata)
		if err != nil {
			return err
		}
	}
	identity := Identity{
		Principal: principal, SourceNode: metadata.SourceNode,
		SourceBinding: metadata.SourceBinding, ChainSHA256: metadata.ChainSHA256,
	}
	return s.Serve(ctx, stream, identity)
}

func (s *Server) Serve(ctx context.Context, stream io.ReadWriteCloser, identity Identity) error {
	if s == nil || s.Manager == nil || stream == nil {
		return errors.New("terminalsession: incomplete server")
	}
	attachment := &wireAttachment{stream: stream, codec: s.Codec}
	first, err := s.Codec.ReadFrame(stream)
	if err != nil {
		_ = attachment.Close()
		return err
	}
	if first.Type != FrameOpen {
		_ = s.sendError(ctx, attachment, "protocol", "first frame must be OPEN")
		_ = attachment.Close()
		return ErrInvalidRequest
	}
	var request OpenRequest
	if err := decodeStrict(first.Payload, &request); err != nil {
		_ = s.sendError(ctx, attachment, "invalid_request", "invalid terminal request")
		_ = attachment.Close()
		return err
	}
	lease, err := s.Manager.Connect(ctx, identity, request, attachment)
	if err != nil {
		code := "unavailable"
		message := "terminal session unavailable"
		if errors.Is(err, ErrDenied) || errors.Is(err, ErrNotFound) {
			code, message = "denied", "terminal session denied"
		} else if errors.Is(err, ErrInvalidRequest) {
			code, message = "invalid_request", "invalid terminal request"
		}
		_ = s.sendError(ctx, attachment, code, message)
		_ = attachment.Close()
		return err
	}

	for {
		frame, readErr := s.Codec.ReadFrame(stream)
		if readErr != nil {
			_ = s.Manager.Detach(lease, "tunnel-read-ended")
			if errors.Is(readErr, io.EOF) || errors.Is(readErr, io.ErrClosedPipe) || ctx.Err() != nil {
				return nil
			}
			return readErr
		}
		switch frame.Type {
		case FrameInput:
			if err := s.Manager.Input(lease, frame.Payload); err != nil {
				return err
			}
		case FrameResize:
			size, err := decodeSize(frame.Payload)
			if err != nil {
				return err
			}
			if err := s.Manager.Resize(ctx, lease, size); err != nil {
				return err
			}
		case FrameDetach:
			return s.Manager.Detach(lease, "client-detach")
		case FrameTerminate:
			return s.Manager.Terminate(lease, "client-terminate")
		case FramePing:
			if err := attachment.Send(ctx, Frame{Type: FramePong}); err != nil {
				return err
			}
		case FramePong:
			// Reserved for server-initiated liveness probes.
		default:
			_ = s.sendError(ctx, attachment, "protocol", "unexpected client frame")
			_ = s.Manager.Detach(lease, "protocol-error")
			return ErrInvalidRequest
		}
	}
}

func (s *Server) sendError(ctx context.Context, attachment Attachment, code, message string) error {
	return sendJSON(ctx, attachment, FrameError, ResponseError{
		Protocol: ProtocolVersion, Code: strings.TrimSpace(code), Message: strings.TrimSpace(message),
	})
}

type wireAttachment struct {
	mu     sync.Mutex
	once   sync.Once
	stream io.ReadWriteCloser
	codec  Codec
}

func (a *wireAttachment) Send(ctx context.Context, frame Frame) error {
	result := make(chan error, 1)
	go func() {
		a.mu.Lock()
		err := a.codec.WriteFrame(a.stream, frame)
		a.mu.Unlock()
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		_ = a.Close()
		return ctx.Err()
	}
}

func (a *wireAttachment) Close() error {
	var err error
	a.once.Do(func() {
		if resetter, ok := a.stream.(interface{ Reset() error }); ok {
			err = resetter.Reset()
			return
		}
		err = a.stream.Close()
	})
	return err
}

func decodeStrict(payload []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidRequest
	}
	return nil
}
