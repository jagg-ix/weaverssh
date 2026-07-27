// Package agentapi exposes the embeddable weaverssh agent runtime.
//
// Use this package when a caller wants the agent protocol handler as an
// in-process library instead of binding a TCP or Unix-domain listener. The
// caller owns the transport and passes accepted in-memory or IPC connections to
// ServeConn.
package agentapi

import (
	"fmt"
	"net"
	"time"

	"weaverssh/authproof"
	"weaverssh/internal/app"
)

type Config struct {
	X11Target      string
	AuthCookie     string
	AuthTimeout    time.Duration
	TrustedAuth    bool
	EnableSecurity bool
	Proof          authproof.RuntimeConfig
}

type Runtime struct {
	inner *app.AgentRuntime
}

func NewRuntime(config Config) (*Runtime, error) {
	if config.AuthCookie == "" {
		return nil, fmt.Errorf("agentapi requires AuthCookie")
	}
	inner, err := app.NewAgentRuntime(app.AgentConfig{
		ListenNetwork:  string(app.AgentInterfaceLibrary),
		InterfaceMode:  string(app.AgentInterfaceLibrary),
		X11Target:      config.X11Target,
		AuthTimeout:    config.AuthTimeout,
		TrustedAuth:    config.TrustedAuth,
		EnableSecurity: config.EnableSecurity,
		Proof:          config.Proof,
	}, config.AuthCookie)
	if err != nil {
		return nil, err
	}
	return &Runtime{inner: inner}, nil
}

func (r *Runtime) ServeConn(conn net.Conn) {
	r.inner.ServeConn(conn)
}

func (r *Runtime) Close() error {
	if r == nil || r.inner == nil {
		return nil
	}
	return r.inner.Close()
}
