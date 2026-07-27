package tunnel

import (
	"weaverssh/flowcontrol"

	"github.com/gorilla/websocket"
)

// WebSocketReadWriter adapts a *websocket.Conn to the io.ReadWriter interface
type WebSocketReadWriter struct {
	Conn        *websocket.Conn
	readBuf     []byte
	flowProfile flowcontrol.Profile
}

// NewWebSocketReadWriter creates a new WebSocket adapter
func NewWebSocketReadWriter(conn *websocket.Conn) *WebSocketReadWriter {
	return NewWebSocketReadWriterWithProfile(conn, flowcontrol.DefaultProfile())
}

// NewWebSocketReadWriterWithProfile creates a WebSocket stream adapter that
// splits writes at the profile's frame boundary. This keeps the WebSocket layer
// aligned with the relay chunk and SSH socket buffering contract.
func NewWebSocketReadWriterWithProfile(conn *websocket.Conn, profile flowcontrol.Profile) *WebSocketReadWriter {
	return &WebSocketReadWriter{
		Conn:        conn,
		readBuf:     nil,
		flowProfile: profile.Normalized(),
	}
}

// Read implements the io.Reader interface for a WebSocket connection
func (w *WebSocketReadWriter) Read(p []byte) (n int, err error) {
	// If we have leftover data from a previous read, use that first
	if len(w.readBuf) > 0 {
		n = copy(p, w.readBuf)
		if n < len(w.readBuf) {
			// Still have data left over
			w.readBuf = w.readBuf[n:]
		} else {
			// Used all the buffer
			w.readBuf = nil
		}
		return n, nil
	}

	// Otherwise, read a new message
	_, message, err := w.Conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	// Copy what we can into the provided buffer
	n = copy(p, message)

	// Store any leftover data for the next Read call
	if n < len(message) {
		w.readBuf = make([]byte, len(message)-n)
		copy(w.readBuf, message[n:])
	}

	return n, nil
}

// Write implements the io.Writer interface for a WebSocket connection
func (w *WebSocketReadWriter) Write(p []byte) (n int, err error) {
	frameBytes := w.flowProfile.Normalized().WebSocketFrameBytes
	if frameBytes <= 0 || len(p) <= frameBytes {
		if err = w.Conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	for off := 0; off < len(p); off += frameBytes {
		end := off + frameBytes
		if end > len(p) {
			end = len(p)
		}
		if err = w.Conn.WriteMessage(websocket.BinaryMessage, p[off:end]); err != nil {
			return off, err
		}
	}
	return len(p), nil
}

// Close closes the underlying WebSocket connection
func (w *WebSocketReadWriter) Close() error {
	return w.Conn.Close()
}
