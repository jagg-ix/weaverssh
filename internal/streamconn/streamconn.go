// Package streamconn adapts an already-open bidirectional stream to net.Conn
// for protocol implementations that only use Read, Write, and Close.
//
// It never dials, listens, or allocates a network port. Deadline operations are
// rejected because a generic logical session stream cannot promise transport-
// level deadline enforcement.
package streamconn

import (
	"errors"
	"io"
	"net"
	"time"
)

// ErrDeadlineUnsupported reports that the wrapped logical stream has no native
// net.Conn deadline mechanism.
var ErrDeadlineUnsupported = errors.New("streamconn: deadlines are not supported by this logical stream")

// Conn wraps an io.ReadWriteCloser as a net.Conn.
type Conn struct {
	io.ReadWriteCloser
	local  net.Addr
	remote net.Addr
}

// Wrap returns transport unchanged when it already implements net.Conn;
// otherwise it returns a logical net.Conn adapter.
func Wrap(transport io.ReadWriteCloser) net.Conn {
	if conn, ok := transport.(net.Conn); ok {
		return conn
	}
	return &Conn{
		ReadWriteCloser: transport,
		local:           addr("weaverssh-session-local"),
		remote:          addr("weaverssh-session-peer"),
	}
}

// LocalAddr returns a synthetic session address.
func (c *Conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns a synthetic peer address.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline is unsupported for a generic logical stream.
func (c *Conn) SetDeadline(time.Time) error { return ErrDeadlineUnsupported }

// SetReadDeadline is unsupported for a generic logical stream.
func (c *Conn) SetReadDeadline(time.Time) error { return ErrDeadlineUnsupported }

// SetWriteDeadline is unsupported for a generic logical stream.
func (c *Conn) SetWriteDeadline(time.Time) error { return ErrDeadlineUnsupported }

type addr string

func (a addr) Network() string { return "weaverssh-session" }
func (a addr) String() string  { return string(a) }
