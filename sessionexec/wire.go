package sessionexec

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
	"sort"
	"strings"
	"sync"
	"time"
)

func (e *Engine) Serve(ctx context.Context, stream io.ReadWriteCloser, raw []byte) error {
	if e == nil || stream == nil {
		return errors.New("sessionexec: incomplete server")
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
	resp, execErr := e.Execute(ctx, m, req)
	if execErr != nil {
		resp.Error = mapError(execErr)
		resp.Protocol = ProtocolVersion
		resp.ID = req.ID
	}
	return writeResponse(stream, resp)
}
func CallStream(ctx context.Context, stream io.ReadWriteCloser, req Request) (Response, error) {
	if stream == nil {
		return Response{}, errors.New("sessionexec: nil stream")
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
		return Response{}, errors.New("sessionexec: response ID mismatch")
	}
	if resp.Error != nil {
		return resp, fmt.Errorf("sessionexec %s: %s", resp.Error.Code, resp.Error.Message)
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
	r.Action = strings.TrimSpace(r.Action)
	r.Args = append([]string(nil), r.Args...)
	return r
}
func validateRequest(r Request) error {
	if r.Protocol != ProtocolVersion || r.ID == "" || len(r.ID) > 128 || !validName(r.Action) || len(r.Args) > MaxArgs || len(r.Stdin) > MaxInputBytes || r.TimeoutMillis < 0 {
		return ErrInvalidRequest
	}
	return nil
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
		return Response{}, errors.New("sessionexec: wrong response protocol")
	}
	return resp, nil
}
func writeFrame(w io.Writer, p []byte) error {
	if len(p) == 0 || len(p) > MaxMessageBytes {
		return errors.New("sessionexec: invalid message size")
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
		return nil, errors.New("sessionexec: invalid message size")
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
		return errors.New("sessionexec: trailing JSON")
	}
	return nil
}
func mapError(err error) *ResponseError {
	code := "internal"
	switch {
	case errors.Is(err, ErrInvalidRequest):
		code = "invalid_request"
	case errors.Is(err, ErrDenied):
		code = "denied"
	case errors.Is(err, ErrActionNotFound):
		code = "action_not_found"
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
	return &ResponseError{Code: code, Message: msg}
}
func errorResponse(id string, err error) Response {
	return Response{Protocol: ProtocolVersion, ID: id, ExitCode: -1, Error: mapError(err)}
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
func validEnvKey(v string) bool {
	if v == "" || len(v) > 128 {
		return false
	}
	for i, r := range v {
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}
func sourceAllowed(values []string, want string) bool {
	for _, v := range values {
		if v == "*" || strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}
func explicitEnv(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+values[k])
	}
	return out
}
func indexOf(values []string, want string) int {
	for i, v := range values {
		if strings.TrimSpace(v) == want {
			return i
		}
	}
	return -1
}

type cappedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
	mu        sync.Mutex
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	remaining := c.max - c.buf.Len()
	if remaining <= 0 {
		c.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		_, _ = c.buf.Write(p[:remaining])
		c.truncated = true
		return len(p), nil
	}
	return c.buf.Write(p)
}
func (c *cappedBuffer) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}
