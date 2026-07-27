package sessionapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"weaverssh/sessionmux"
)

var requestCounter atomic.Uint64

func Open(ctx context.Context, mux *sessionmux.Mux) (*sessionmux.Stream, error) {
	if mux == nil {
		return nil, errors.New("sessionapi: nil mux")
	}
	return mux.Open(ctx, sessionmux.ServiceControl, []byte(ProtocolVersion))
}

func Call(ctx context.Context, mux *sessionmux.Mux, method string, params any, result any) error {
	stream, err := Open(ctx, mux)
	if err != nil {
		return err
	}
	defer stream.Close()
	return CallStream(ctx, stream, method, params, result)
}

func CallStream(ctx context.Context, stream io.ReadWriter, method string, params any, result any) error {
	if stream == nil {
		return errors.New("sessionapi: nil stream")
	}
	request := Request{Protocol: ProtocolVersion, ID: fmt.Sprintf("req-%d", requestCounter.Add(1)), Method: method}
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return err
		}
		request.Params = encoded
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := writeMessage(stream, payload); err != nil {
		return err
	}

	type decoded struct {
		response Response
		err      error
	}
	responseCh := make(chan decoded, 1)
	go func() {
		payload, err := readMessage(stream)
		if err != nil {
			responseCh <- decoded{err: err}
			return
		}
		var response Response
		err = json.Unmarshal(payload, &response)
		responseCh <- decoded{response: response, err: err}
	}()
	select {
	case item := <-responseCh:
		if item.err != nil {
			return fmt.Errorf("sessionapi: decode response: %w", item.err)
		}
		if item.response.Protocol != ProtocolVersion || item.response.ID != request.ID {
			return ErrWrongProtocol
		}
		if item.response.Error != nil {
			return fmt.Errorf("sessionapi: %s: %s", item.response.Error.Code, item.response.Error.Message)
		}
		if result != nil {
			if len(item.response.Result) == 0 {
				return errors.New("sessionapi: response has no result")
			}
			if err := json.Unmarshal(item.response.Result, result); err != nil {
				return err
			}
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func writeFull(writer io.Writer, payload []byte) error {
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
