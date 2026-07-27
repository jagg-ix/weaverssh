package tunnel

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/websocket"
)

type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Sleep          func(time.Duration)
	IsRecoverable  func(error) bool
}

// WebSocketClient handles WebSocket client connections
type WebSocketClient struct {
	conn     *websocket.Conn
	endpoint string
}

// NewWebSocketClient creates a new WebSocket client
func NewWebSocketClient(endpoint string) *WebSocketClient {
	return &WebSocketClient{
		endpoint: endpoint,
	}
}

// Connect establishes a WebSocket connection
func (c *WebSocketClient) Connect() error {
	return c.ConnectWithPolicy(DefaultRetryPolicy())
}

func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxAttempts:    3,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     time.Second,
	}
}

func normalizeRetryPolicy(policy RetryPolicy) RetryPolicy {
	defaults := DefaultRetryPolicy()
	if policy.MaxAttempts <= 0 {
		policy.MaxAttempts = defaults.MaxAttempts
	}
	if policy.InitialBackoff <= 0 {
		policy.InitialBackoff = defaults.InitialBackoff
	}
	if policy.MaxBackoff <= 0 {
		policy.MaxBackoff = defaults.MaxBackoff
	}
	if policy.Sleep == nil {
		policy.Sleep = time.Sleep
	}
	return policy
}

func retryBackoff(policy RetryPolicy, attempt int) time.Duration {
	if attempt <= 1 {
		return policy.InitialBackoff
	}
	backoff := policy.InitialBackoff
	for i := 1; i < attempt; i++ {
		backoff *= 2
		if backoff >= policy.MaxBackoff {
			return policy.MaxBackoff
		}
	}
	return backoff
}

// ConnectWithPolicy establishes a WebSocket connection using bounded retry
// and monotone backoff. Non-recoverable errors fail closed immediately.
func (c *WebSocketClient) ConnectWithPolicy(policy RetryPolicy) error {
	return c.connectWithPolicy(policy, websocket.DefaultDialer.Dial)
}

type websocketDialFunc func(string, http.Header) (*websocket.Conn, *http.Response, error)

func (c *WebSocketClient) connectWithPolicy(policy RetryPolicy, dial websocketDialFunc) error {
	// Parse the endpoint
	u, err := url.Parse(c.endpoint)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint: %v", err)
	}

	// Add scheme if missing
	if u.Scheme == "" {
		u.Scheme = "ws"
	}

	policy = normalizeRetryPolicy(policy)
	var lastErr error
	for attempt := 1; attempt <= policy.MaxAttempts; attempt++ {
		conn, _, err := dial(u.String(), nil)
		if err == nil && conn != nil {
			c.conn = conn
			log.Printf("Connected to WebSocket endpoint: %s (attempt %d/%d)", u.String(), attempt, policy.MaxAttempts)
			return nil
		}
		if err == nil {
			err = fmt.Errorf("websocket dial returned nil connection")
		}

		lastErr = err
		if policy.IsRecoverable != nil && !policy.IsRecoverable(err) {
			return fmt.Errorf("failed to connect to WebSocket: non-recoverable after attempt %d/%d: %w", attempt, policy.MaxAttempts, err)
		}
		if attempt < policy.MaxAttempts {
			policy.Sleep(retryBackoff(policy, attempt))
		}
	}

	return fmt.Errorf("failed to connect to WebSocket after %d attempts: %w", policy.MaxAttempts, lastErr)
}

// GetConnection returns the underlying WebSocket connection
func (c *WebSocketClient) GetConnection() *websocket.Conn {
	return c.conn
}

// Close closes the WebSocket connection
func (c *WebSocketClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Send sends a message over the WebSocket connection
func (c *WebSocketClient) Send(data []byte) error {
	if c.conn == nil {
		return fmt.Errorf("connection not established")
	}
	return c.conn.WriteMessage(websocket.BinaryMessage, data)
}

// Receive receives a message from the WebSocket connection
func (c *WebSocketClient) Receive() ([]byte, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("connection not established")
	}
	_, message, err := c.conn.ReadMessage()
	return message, err
}
