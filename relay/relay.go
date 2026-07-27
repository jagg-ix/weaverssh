package relay

import (
	"io"
	"log"
	"sync"
	"time"

	"weaverssh/flowcontrol"

	"github.com/gorilla/websocket"
)

// ByteCounter is a callback function for tracking bytes
type ByteCounter func(n int)

// Relay manages bidirectional data transfer
type Relay struct {
	wsConn          *websocket.Conn
	byteSentCounter ByteCounter
	byteRecvCounter ByteCounter
	sessionID       string
	targetAddr      string
	startTime       time.Time
	lastActivity    time.Time
	bytesSent       int64
	bytesReceived   int64
	hasStarted      bool
	isActive        bool
	flowProfile     flowcontrol.Profile
	mu              sync.RWMutex
}

// NewRelay creates a new relay
func NewRelay(wsConn *websocket.Conn) *Relay {
	return NewRelayWithProfile(wsConn, flowcontrol.DefaultProfile())
}

// NewRelayWithProfile creates a relay with an explicit cross-layer flow
// profile. The profile drives relay read chunk size and socket latency options.
func NewRelayWithProfile(wsConn *websocket.Conn, profile flowcontrol.Profile) *Relay {
	return &Relay{
		wsConn:       wsConn,
		startTime:    time.Now(),
		lastActivity: time.Now(),
		isActive:     false,
		flowProfile:  profile.Normalized(),
	}
}

// SetFlowProfile updates the relay buffering profile before Start.
func (r *Relay) SetFlowProfile(profile flowcontrol.Profile) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.flowProfile = profile.Normalized()
}

// SetByteCounters sets callback functions for tracking bytes
func (r *Relay) SetByteCounters(sentCounter, recvCounter ByteCounter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byteSentCounter = sentCounter
	r.byteRecvCounter = recvCounter
}

// SetSessionInfo sets session information for the relay
func (r *Relay) SetSessionInfo(sessionID, targetAddr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessionID = sessionID
	r.targetAddr = targetAddr
}

// updateLastActivity updates the last activity timestamp
func (r *Relay) updateLastActivity() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastActivity = time.Now()
}

// trackBytesSent updates bytes sent counter
func (r *Relay) trackBytesSent(n int) {
	r.mu.Lock()
	r.bytesSent += int64(n)
	r.lastActivity = time.Now()
	counter := r.byteSentCounter
	r.mu.Unlock()

	if counter != nil {
		counter(n)
	}
}

// trackBytesReceived updates bytes received counter
func (r *Relay) trackBytesReceived(n int) {
	r.mu.Lock()
	r.bytesReceived += int64(n)
	r.lastActivity = time.Now()
	counter := r.byteRecvCounter
	r.mu.Unlock()

	if counter != nil {
		counter(n)
	}
}

// GetStats returns relay statistics
func (r *Relay) GetStats() (time.Time, time.Time, int64, int64, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.startTime, r.lastActivity, r.bytesSent, r.bytesReceived, r.isActive
}

func (r *Relay) beginStart() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hasStarted {
		return false
	}
	r.hasStarted = true
	r.isActive = true
	r.startTime = time.Now()
	r.lastActivity = r.startTime
	return true
}

func (r *Relay) profile() flowcontrol.Profile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.flowProfile.Normalized()
}

func (r *Relay) markInactive() {
	r.mu.Lock()
	r.isActive = false
	r.lastActivity = time.Now()
	r.mu.Unlock()
}

func (r *Relay) isReapable() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hasStarted && !r.isActive
}

// Start begins bidirectional data transfer between WebSocket and connection
func (r *Relay) Start(conn io.ReadWriter) {
	if !r.beginStart() {
		log.Printf("Relay already started")
		return
	}
	profile := r.profile()
	if err := flowcontrol.ApplySocketOptions(conn, profile); err != nil {
		log.Printf("Relay socket option warning: %v", err)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	var shutdownOnce sync.Once
	shutdown := func() {
		shutdownOnce.Do(func() {
			if r.wsConn != nil {
				deadline := time.Now().Add(time.Second)
				_ = r.wsConn.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
					deadline,
				)
				_ = r.wsConn.Close()
			}
			if closer, ok := conn.(io.Closer); ok {
				_ = closer.Close()
			}
		})
	}

	// Log start of relay
	if r.sessionID != "" && r.targetAddr != "" {
		log.Printf("Starting relay %s to %s", r.sessionID, r.targetAddr)
	} else {
		log.Printf("Starting relay")
	}

	// WebSocket to connection
	go func() {
		defer wg.Done()
		for {
			messageType, message, err := r.wsConn.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("WebSocket closed normally")
				} else {
					log.Printf("WebSocket read error: %v", err)
				}
				break
			}

			if messageType != websocket.BinaryMessage {
				log.Printf("Received non-binary message type: %d", messageType)
				continue
			}

			n, err := conn.Write(message)
			if err != nil {
				log.Printf("Connection write error: %v", err)
				break
			}

			// Track bytes sent to target
			r.trackBytesSent(n)
		}

		shutdown()
	}()

	// Connection to WebSocket
	go func() {
		defer wg.Done()
		buffer := make([]byte, profile.RelayReadBytes)
		for {
			n, err := conn.Read(buffer)
			if err != nil {
				if err != io.EOF {
					log.Printf("Connection read error: %v", err)
				}
				break
			}

			// Track bytes received from target
			r.trackBytesReceived(n)

			err = r.wsConn.WriteMessage(websocket.BinaryMessage, buffer[:n])
			if err != nil {
				log.Printf("WebSocket write error: %v", err)
				break
			}
		}

		shutdown()
	}()

	// Wait for both goroutines to complete
	wg.Wait()

	r.markInactive()

	// Log relay stats
	startTime, lastActivity, bytesSent, bytesReceived, _ := r.GetStats()
	duration := time.Since(startTime)
	idleTime := time.Since(lastActivity)

	if r.sessionID != "" {
		log.Printf("Relay %s finished. Duration: %v, Idle: %v, Sent: %d bytes, Received: %d bytes",
			r.sessionID, duration.Round(time.Second), idleTime.Round(time.Second), bytesSent, bytesReceived)
	} else {
		log.Printf("Relay finished. Duration: %v, Idle: %v, Sent: %d bytes, Received: %d bytes",
			duration.Round(time.Second), idleTime.Round(time.Second), bytesSent, bytesReceived)
	}
}
