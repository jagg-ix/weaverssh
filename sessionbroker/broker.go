// Package sessionbroker exposes an active dynamic session to other local wv
// processes through a Unix-domain or otherwise caller-supplied local listener.
// It never opens a TCP listener itself and never assigns an SSH forwarding port.
package sessionbroker

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"weaverssh/sessionmux"
)

const (
	protocolVersion = "weaverssh.session-broker.v1"
	maxRequestBytes = 64 << 10
)

// OpenRequest selects one authenticated session node and logical service.
type OpenRequest struct {
	Protocol string               `json:"protocol"`
	Node     string               `json:"node"`
	Service  sessionmux.ServiceID `json:"service"`
	Data     []byte               `json:"data,omitempty"`
}

// OpenFunc opens a logical service stream in the active dynamic session.
type OpenFunc func(context.Context, OpenRequest) (io.ReadWriteCloser, error)

// Server bridges local broker connections to logical dynamic-session streams.
type Server struct {
	Open OpenFunc
}

// Serve accepts local clients until ctx is cancelled or listener closes.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s == nil || s.Open == nil {
		return errors.New("sessionbroker: missing open function")
	}
	if listener == nil {
		return errors.New("sessionbroker: nil listener")
	}
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) error {
	defer conn.Close()
	request, err := readRequest(conn)
	if err != nil {
		_ = writeResponse(conn, err)
		return err
	}
	stream, err := s.Open(ctx, request)
	if err != nil {
		_ = writeResponse(conn, err)
		return err
	}
	defer stream.Close()
	if err := writeResponse(conn, nil); err != nil {
		return err
	}

	type copyResult struct{ err error }
	results := make(chan copyResult, 2)
	go func() {
		_, copyErr := io.Copy(stream, conn)
		// Stream.Close is a local write-half close in sessionmux: peer reads see
		// EOF, while peer writes may continue until their own CLOSE.
		_ = stream.Close()
		results <- copyResult{err: copyErr}
	}()
	go func() {
		_, copyErr := io.Copy(conn, stream)
		if closer, ok := conn.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
		results <- copyResult{err: copyErr}
	}()

	var terminalErr error
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if !normalRelayError(result.err) && terminalErr == nil {
				terminalErr = result.err
				_ = conn.Close()
				_ = stream.Close()
			}
		case <-ctx.Done():
			_ = conn.Close()
			_ = stream.Close()
			return ctx.Err()
		}
	}
	return terminalErr
}

// Dial opens a local broker connection and leaves it in raw service-stream mode.
func Dial(ctx context.Context, network, address string, request OpenRequest) (net.Conn, error) {
	if request.Protocol == "" {
		request.Protocol = protocolVersion
	}
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := writeRequest(conn, request); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := readResponse(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func writeRequest(w io.Writer, request OpenRequest) error {
	if request.Protocol == "" {
		request.Protocol = protocolVersion
	}
	if request.Protocol != protocolVersion || request.Node == "" || !request.Service.Valid() {
		return errors.New("sessionbroker: invalid open request")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(payload) > maxRequestBytes {
		return errors.New("sessionbroker: open request too large")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeFull(w, header); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func readRequest(r io.Reader) (OpenRequest, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return OpenRequest{}, err
	}
	length := binary.BigEndian.Uint32(header)
	if length == 0 || length > maxRequestBytes {
		return OpenRequest{}, errors.New("sessionbroker: invalid request length")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return OpenRequest{}, err
	}
	var request OpenRequest
	if err := json.Unmarshal(payload, &request); err != nil {
		return OpenRequest{}, err
	}
	if request.Protocol != protocolVersion || request.Node == "" || !request.Service.Valid() {
		return OpenRequest{}, errors.New("sessionbroker: invalid open request")
	}
	return request, nil
}

func writeResponse(w io.Writer, responseErr error) error {
	status := byte(0)
	message := ""
	if responseErr != nil {
		status = 1
		message = responseErr.Error()
	}
	payload := []byte(message)
	if len(payload) > maxRequestBytes {
		payload = payload[:maxRequestBytes]
	}
	header := make([]byte, 5)
	header[0] = status
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)))
	if err := writeFull(w, header); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func readResponse(r io.Reader) error {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length > maxRequestBytes {
		return errors.New("sessionbroker: invalid response length")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	if header[0] != 0 {
		return fmt.Errorf("sessionbroker: target denied: %s", string(payload))
	}
	return nil
}

func writeFull(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := w.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func normalRelayError(err error) bool {
	return err == nil ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, net.ErrClosed)
}

// State describes one foreground attach process and its local broker socket.
type State struct {
	Version   string    `json:"version"`
	PID       int       `json:"pid"`
	Socket    string    `json:"socket"`
	Binding   string    `json:"binding"`
	Node      string    `json:"node"`
	StartedAt time.Time `json:"started_at"`
}

// DefaultPaths returns per-user runtime paths without allocating any port.
func DefaultPaths() (socketPath, statePath string, err error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base == "" {
		base, err = os.UserCacheDir()
		if err != nil {
			return "", "", err
		}
	}
	dir := filepath.Join(base, "weaverssh")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	return filepath.Join(dir, "session.sock"), filepath.Join(dir, "session.json"), nil
}

// WriteState writes attach metadata atomically with user-only permissions.
func WriteState(path string, state State) error {
	state.Version = protocolVersion
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
