package sessionbind

import (
	"fmt"
	"net"
	"strings"
)

// OpenClientStream consumes the initial bound response from an already-open
// routed BIND stream and returns the one-shot listener abstraction.
func OpenClientStream(conn net.Conn) (*Listener, error) {
	if conn == nil {
		return nil, net.ErrClosed
	}
	response, err := readResponse(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if response.Phase != "bound" || strings.TrimSpace(response.Error) != "" {
		_ = conn.Close()
		return nil, fmt.Errorf("sessionbind: bind failed: %s", response.Error)
	}
	bound, err := resolveAddr(response.Network, response.Address)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &Listener{conn: conn, bound: bound}, nil
}
