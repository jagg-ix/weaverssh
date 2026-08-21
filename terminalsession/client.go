package terminalsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Client speaks one terminal-session protocol over an already routed stream.
// It does not discover nodes, open listeners, or authenticate independently.
type Client struct {
	stream io.ReadWriteCloser
	codec  Codec
	mu     sync.Mutex
	close  sync.Once
	closed error
}

func NewClient(stream io.ReadWriteCloser, codec Codec) (*Client, error) {
	if stream == nil {
		return nil, errors.New("terminalsession: client stream is required")
	}
	return &Client{stream: stream, codec: codec}, nil
}

func (c *Client) Negotiate(ctx context.Context, request OpenRequest) (Ready, error) {
	if c == nil || c.stream == nil {
		return Ready{}, errors.New("terminalsession: client unavailable")
	}
	if err := request.validate(); err != nil {
		return Ready{}, err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return Ready{}, err
	}
	if err := c.send(ctx, Frame{Type: FrameOpen, Payload: payload}); err != nil {
		return Ready{}, err
	}
	frame, err := c.readFrame(ctx)
	if err != nil {
		return Ready{}, err
	}
	switch frame.Type {
	case FrameReady:
		var ready Ready
		if err := decodeStrict(frame.Payload, &ready); err != nil {
			return Ready{}, fmt.Errorf("terminalsession: invalid READY: %w", err)
		}
		if ready.Protocol != ProtocolVersion || ready.SessionID == "" || ready.Generation == 0 || !validReadyBounds(ready) {
			return Ready{}, errors.New("terminalsession: invalid READY payload")
		}
		if request.Operation == OperationConnect && (ready.State != StateActive || ready.ResumeToken == "") {
			return Ready{}, errors.New("terminalsession: invalid connect READY payload")
		}
		if request.Operation == OperationReattach && (ready.State != StateRecovering || ready.SessionID != request.SessionID || ready.ResumeToken != "") {
			return Ready{}, errors.New("terminalsession: invalid reattach READY payload")
		}
		return ready, nil
	case FrameError:
		return Ready{}, decodeRemoteError(frame.Payload)
	default:
		return Ready{}, fmt.Errorf("terminalsession: expected READY or ERROR, got frame %d", frame.Type)
	}
}

func validReadyBounds(ready Ready) bool {
	if ready.ReplayCeiling == 0 {
		return ready.ReplayFloor == 1
	}
	return ready.ReplayFloor >= 1 && ready.ReplayFloor <= ready.ReplayCeiling+1
}

// ReadEvent reads one agent-to-client data or control event.
func (c *Client) ReadEvent() (Frame, error) {
	if c == nil || c.stream == nil {
		return Frame{}, errors.New("terminalsession: client unavailable")
	}
	frame, err := c.codec.ReadFrame(c.stream)
	if err != nil {
		return Frame{}, err
	}
	switch frame.Type {
	case FrameOutput, FrameExit, FramePing, FrameError:
		if frame.Type == FrameError {
			return Frame{}, decodeRemoteError(frame.Payload)
		}
		return frame, nil
	default:
		return Frame{}, fmt.Errorf("terminalsession: unexpected agent frame %d", frame.Type)
	}
}

func (c *Client) SendInput(ctx context.Context, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}
	return c.send(ctx, Frame{Type: FrameInput, Payload: append([]byte(nil), payload...)})
}

func (c *Client) Resize(ctx context.Context, size TerminalSize) error {
	if err := size.Validate(); err != nil {
		return err
	}
	return c.send(ctx, Frame{Type: FrameResize, Payload: encodeSize(size)})
}

func (c *Client) Detach(ctx context.Context) error {
	return c.send(ctx, Frame{Type: FrameDetach})
}

func (c *Client) Terminate(ctx context.Context) error {
	return c.send(ctx, Frame{Type: FrameTerminate})
}

func (c *Client) Pong(ctx context.Context) error { return c.send(ctx, Frame{Type: FramePong}) }

func (c *Client) send(ctx context.Context, frame Frame) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	result := make(chan error, 1)
	go func() {
		c.mu.Lock()
		err := c.codec.WriteFrame(c.stream, frame)
		c.mu.Unlock()
		result <- err
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		_ = c.Close()
		return ctx.Err()
	}
}

func (c *Client) readFrame(ctx context.Context) (Frame, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	type result struct {
		frame Frame
		err   error
	}
	complete := make(chan result, 1)
	go func() {
		frame, err := c.codec.ReadFrame(c.stream)
		complete <- result{frame: frame, err: err}
	}()
	select {
	case result := <-complete:
		return result.frame, result.err
	case <-ctx.Done():
		_ = c.Close()
		return Frame{}, ctx.Err()
	}
}

func (c *Client) Close() error {
	if c == nil || c.stream == nil {
		return nil
	}
	c.close.Do(func() { c.closed = c.stream.Close() })
	return c.closed
}

func DecodeExit(payload []byte) (Exit, error) {
	var exit Exit
	if err := decodeStrict(payload, &exit); err != nil {
		return Exit{}, err
	}
	if exit.Protocol != ProtocolVersion {
		return Exit{}, errors.New("terminalsession: invalid exit payload")
	}
	return exit, nil
}

func decodeRemoteError(payload []byte) error {
	var response ResponseError
	if err := decodeStrict(payload, &response); err != nil {
		return errors.New("terminalsession: remote rejected request")
	}
	if response.Protocol != ProtocolVersion {
		return errors.New("terminalsession: remote rejected request")
	}
	return fmt.Errorf("terminalsession: remote %s: %s", response.Code, response.Message)
}
