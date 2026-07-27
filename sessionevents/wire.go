package sessionevents

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"weaverssh/pubsub"
)

func (e *Engine) Serve(ctx context.Context, stream io.ReadWriteCloser, raw []byte) error {
	if e == nil || stream == nil {
		return errors.New("sessionevents: incomplete server")
	}
	defer stream.Close()
	m, err := ParseOpenMetadata(raw)
	if err != nil {
		return err
	}
	req, err := readRequest(stream)
	if err != nil {
		_ = writeResponse(stream, errorResponse("", err))
		return nil
	}
	if err := e.authorize(m, req); err != nil {
		return writeResponse(stream, errorResponse(req.ID, err))
	}
	switch req.Operation {
	case OperationPublish:
		if err := e.bus.Publish(req.Topic, req.Payload); err != nil {
			return writeResponse(stream, errorResponse(req.ID, err))
		}
		return writeResponse(stream, Response{Protocol: ProtocolVersion, ID: req.ID, Kind: "published", Topic: req.Topic, Delivered: 1})
	case OperationSubscribe:
		return e.serveSubscription(ctx, stream, req)
	default:
		return writeResponse(stream, errorResponse(req.ID, ErrInvalidRequest))
	}
}
func (e *Engine) serveSubscription(ctx context.Context, stream io.ReadWriteCloser, req Request) error {
	buffer := req.Buffer
	if buffer == 0 {
		buffer = 64
	}
	ch, cancel, err := e.bus.Subscribe(req.Topic, buffer)
	if err != nil {
		return writeResponse(stream, errorResponse(req.ID, err))
	}
	defer cancel()
	if err := writeResponse(stream, Response{Protocol: ProtocolVersion, ID: req.ID, Kind: "subscribed", Topic: req.Topic}); err != nil {
		return err
	}
	disconnected := make(chan error, 1)
	go func() {
		var probe [1]byte
		_, err := stream.Read(probe[:])
		disconnected <- err
	}()
	sent := 0
	for req.Limit == 0 || sent < req.Limit {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-disconnected:
			if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
				return nil
			}
			return err
		case msg, ok := <-ch:
			if !ok {
				return nil
			}
			sent++
			if err := writeResponse(stream, Response{Protocol: ProtocolVersion, ID: req.ID, Kind: "message", Topic: msg.Topic, Payload: msg.Payload, Delivered: sent}); err != nil {
				return err
			}
		}
	}
	return nil
}

func PublishStream(ctx context.Context, stream io.ReadWriteCloser, topic string, payload []byte) (Response, error) {
	req := Request{Protocol: ProtocolVersion, ID: NewRequestID(), Operation: OperationPublish, Topic: strings.TrimSpace(topic), Payload: append([]byte(nil), payload...)}
	return callOne(ctx, stream, req)
}
func SubscribeStream(ctx context.Context, stream io.ReadWriteCloser, filter string, limit, buffer int, fn func(Response) error) error {
	if stream == nil {
		return errors.New("sessionevents: nil stream")
	}
	defer stream.Close()
	req := normalizeRequest(Request{ID: NewRequestID(), Operation: OperationSubscribe, Topic: strings.TrimSpace(filter), Limit: limit, Buffer: buffer})
	if err := validateRequest(req); err != nil {
		return err
	}
	if err := writeRequest(stream, req); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
		case <-done:
		}
	}()
	defer close(done)
	ack, err := readResponse(stream)
	if err != nil {
		return err
	}
	if ack.Error != nil {
		return fmt.Errorf("sessionevents %s: %s", ack.Error.Code, ack.Error.Message)
	}
	if ack.Kind != "subscribed" || ack.ID != req.ID {
		return errors.New("sessionevents: invalid subscription acknowledgement")
	}
	received := 0
	for limit == 0 || received < limit {
		resp, err := readResponse(stream)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if resp.Error != nil {
			return fmt.Errorf("sessionevents %s: %s", resp.Error.Code, resp.Error.Message)
		}
		if resp.ID != req.ID || resp.Kind != "message" {
			return errors.New("sessionevents: invalid message response")
		}
		received++
		if fn != nil {
			if err := fn(resp); err != nil {
				return err
			}
		}
	}
	return nil
}
func callOne(ctx context.Context, stream io.ReadWriteCloser, req Request) (Response, error) {
	if stream == nil {
		return Response{}, errors.New("sessionevents: nil stream")
	}
	defer stream.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = stream.Close()
		case <-done:
		}
	}()
	defer close(done)
	req = normalizeRequest(req)
	if err := validateRequest(req); err != nil {
		return Response{}, err
	}
	if err := writeRequest(stream, req); err != nil {
		return Response{}, err
	}
	resp, err := readResponse(stream)
	if err != nil {
		return Response{}, err
	}
	if resp.ID != req.ID {
		return Response{}, errors.New("sessionevents: response ID mismatch")
	}
	if resp.Error != nil {
		return resp, fmt.Errorf("sessionevents %s: %s", resp.Error.Code, resp.Error.Message)
	}
	return resp, nil
}
func NewRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
func normalizeRequest(r Request) Request {
	r.Protocol = ProtocolVersion
	r.ID = strings.TrimSpace(r.ID)
	if r.ID == "" {
		r.ID = NewRequestID()
	}
	r.Operation = strings.ToLower(strings.TrimSpace(r.Operation))
	r.Topic = strings.TrimSpace(r.Topic)
	if r.Buffer == 0 {
		r.Buffer = 64
	}
	return r
}
func validateRequest(r Request) error {
	if r.Protocol != ProtocolVersion || r.ID == "" || len(r.ID) > 128 || (r.Operation != OperationPublish && r.Operation != OperationSubscribe) || r.Limit < 0 || r.Limit > MaxSubscriptionLimit || r.Buffer < 0 || r.Buffer > 65536 || len(r.Payload) > MaxPayloadBytes {
		return ErrInvalidRequest
	}
	if r.Operation == OperationPublish {
		if len(r.Payload) == 0 {
			return ErrInvalidRequest
		}
		return pubsub.ValidatePublishTopic(r.Topic)
	}
	if len(r.Payload) != 0 {
		return ErrInvalidRequest
	}
	return pubsub.ValidateSubscribeTopic(r.Topic)
}
func writeRequest(w io.Writer, r Request) error {
	p, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeFrame(w, p)
}
func readRequest(r io.Reader) (Request, error) {
	p, err := readFrame(r)
	if err != nil {
		return Request{}, err
	}
	var req Request
	if err := decodeStrict(p, &req); err != nil {
		return Request{}, err
	}
	req = normalizeRequest(req)
	return req, validateRequest(req)
}
func writeResponse(w io.Writer, r Response) error {
	r.Protocol = ProtocolVersion
	p, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return writeFrame(w, p)
}
func readResponse(r io.Reader) (Response, error) {
	p, err := readFrame(r)
	if err != nil {
		return Response{}, err
	}
	var resp Response
	if err := decodeStrict(p, &resp); err != nil {
		return Response{}, err
	}
	if resp.Protocol != ProtocolVersion {
		return Response{}, errors.New("sessionevents: wrong response protocol")
	}
	return resp, nil
}
func writeFrame(w io.Writer, p []byte) error {
	if len(p) == 0 || len(p) > MaxMessageBytes {
		return errors.New("sessionevents: invalid message size")
	}
	h := make([]byte, 4)
	binary.BigEndian.PutUint32(h, uint32(len(p)))
	if err := writeAll(w, h); err != nil {
		return err
	}
	return writeAll(w, p)
}
func readFrame(r io.Reader) ([]byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(r, h); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h)
	if n == 0 || n > MaxMessageBytes {
		return nil, errors.New("sessionevents: invalid message size")
	}
	p := make([]byte, n)
	_, err := io.ReadFull(r, p)
	return p, err
}
func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
func decodeStrict(p []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(p))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	var trailing any
	if err := d.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("sessionevents: trailing JSON")
	}
	return nil
}
func errorResponse(id string, err error) Response {
	code := "internal"
	switch {
	case errors.Is(err, ErrInvalidRequest):
		code = "invalid_request"
	case errors.Is(err, ErrDenied):
		code = "denied"
	case errors.Is(err, ErrLimitExceeded):
		code = "limit_exceeded"
	case errors.Is(err, context.DeadlineExceeded):
		code = "deadline_exceeded"
	case errors.Is(err, context.Canceled):
		code = "canceled"
	}
	msg := err.Error()
	if len(msg) > 4096 {
		msg = msg[:4096]
	}
	return Response{Protocol: ProtocolVersion, ID: id, Kind: "error", Error: &ResponseError{Code: code, Message: msg}}
}
func filterCovered(allowed, requested string) bool {
	allowed = strings.TrimSpace(allowed)
	requested = strings.TrimSpace(requested)
	if allowed == requested || allowed == "#" {
		return true
	}
	a := strings.Split(allowed, "/")
	r := strings.Split(requested, "/")
	for i, part := range a {
		if part == "#" {
			return i == len(a)-1
		}
		if i >= len(r) || r[i] == "#" {
			return false
		}
		if part == "+" {
			continue
		}
		if r[i] != part {
			return false
		}
	}
	return len(a) == len(r)
}
func sourceMatches(values []string, want string) bool {
	for _, v := range values {
		if v == "*" || strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}
func contains(values []string, want string) bool {
	for _, v := range values {
		if strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}
func validName(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r == '.' || r == '_' || r == '-' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
func indexOf(values []string, want string) int {
	for i, v := range values {
		if strings.TrimSpace(v) == want {
			return i
		}
	}
	return -1
}
