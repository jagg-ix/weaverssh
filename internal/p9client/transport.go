package p9client

import (
	"errors"
	"io"

	"weaverssh/internal/streamconn"
)

// Attach starts a 9P client session over an already-open bidirectional stream.
// The caller may supply a sessionmux.Stream or another authenticated transport.
// Attach does not dial an endpoint or allocate a network port.
func Attach(transport io.ReadWriteCloser) (*Client, error) {
	if transport == nil {
		return nil, errors.New("p9client: nil transport")
	}
	return attach(streamconn.Wrap(transport))
}
