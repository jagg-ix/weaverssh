package p9svc

import (
	"context"
	"errors"
	"io"

	"weaverssh/internal/streamconn"
)

// ServeTransport serves one 9P session over an already-open bidirectional
// stream, such as a sessionmux fs stream. It does not bind or allocate a TCP
// port. The supplied stream is closed when the 9P session ends.
func (s *Server) ServeTransport(transport io.ReadWriteCloser) error {
	return s.ServeTransportContext(context.Background(), transport)
}

// ServeTransportContext is ServeTransport with lifecycle cancellation and the
// optional protocol-aware file backend controller.
func (s *Server) ServeTransportContext(ctx context.Context, transport io.ReadWriteCloser) error {
	if s == nil {
		return errors.New("p9svc: nil server")
	}
	if transport == nil {
		return errors.New("p9svc: nil transport")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	controlled := transport
	if backend := backendAPI(s); backend != nil {
		controlled = newBackendTransport(ctx, transport, backend)
	}
	conn := streamconn.Wrap(controlled)
	defer conn.Close()
	return s.handleConn(conn)
}
