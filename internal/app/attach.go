package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/display"
	"weaverssh/extension"
	"weaverssh/sessionapi"
	"weaverssh/sessionbroker"
	"weaverssh/sessioncontrol"
	"weaverssh/sessiondispatch"
	"weaverssh/sessionlink"
	"weaverssh/sessionmux"
	"weaverssh/sessionroute"
	"weaverssh/sessionruntime"
)

type AttachConfig struct {
	AuthCookie    string
	SignedContext authproof.SignedNodeContext
	RuntimeProof  *authproof.SignedGrant
	DialTimeout   time.Duration
	Dial          func(context.Context, string, string) (net.Conn, error)
	LocalServices *LocalServices
	Extensions    *extension.Registry

	// ReconnectIdentity and ReconnectPrivateKey enable challenge-bound reusable
	// registration. Both must be supplied together. Legacy one-shot registration
	// remains available when they are absent.
	ReconnectIdentity   *authproof.SignedReconnectIdentity
	ReconnectPrivateKey ed25519.PrivateKey

	PreviousNode        string
	HopDepth            int
	EncodedWVHop        string
	RouteStorePath      string
	RouteLeaseStorePath string
}

type AttachedSession struct {
	Session          *sessionruntime.Session
	Endpoint         display.Endpoint
	Registration     sessioncontrol.RegisterResponse
	RegistrationMode sessioncontrol.RegistrationMode
	Node             string
	Context          authproof.NodeContext
	LinkID           sessionlink.ID
	TransportID      sessionlink.TransportID
	Local            *LocalServices
	Router           *sessionroute.Router
	serviceDone      chan error
}

// Close preserves the historical lifecycle contract for direct callers.
// Supervisors use CloseTransport so shared local services survive replacement.
func (a *AttachedSession) Close() error {
	if a == nil {
		return nil
	}
	uninstallMapReduce(a.Local)
	return a.CloseTransport()
}

// CloseTransport disposes only the current SSH/X11/WebSocket transport.
func (a *AttachedSession) CloseTransport() error {
	if a == nil || a.Session == nil {
		return nil
	}
	return a.Session.Close()
}

func (a *AttachedSession) ServiceDone() <-chan error {
	if a == nil {
		return nil
	}
	return a.serviceDone
}

// OpenBroker dispatches a local broker request through this exact transport.
// A sessionbroker.LinkRouter publishes this function only while the generation
// is ready.
func (a *AttachedSession) OpenBroker(ctx context.Context, request sessionbroker.OpenRequest) (io.ReadWriteCloser, error) {
	if a == nil || a.Session == nil || a.Session.Mux == nil || a.Router == nil {
		return nil, sessionbroker.ErrNoActiveSession
	}
	if request.Service == sessionmux.ServiceControl {
		return sessionapi.Open(ctx, a.Session.Mux)
	}
	return OpenBrokerTarget(ctx, a.Local, a.Router, a.Session.Binding, a.Context, request)
}

func AttachDynamicSession(ctx context.Context, config AttachConfig) (*AttachedSession, error) {
	if strings.TrimSpace(config.SignedContext.Signature) == "" {
		return nil, errors.New("attach: signed node context is required")
	}
	if err := config.SignedContext.Context.Validate(); err != nil {
		return nil, fmt.Errorf("attach: node context: %w", err)
	}
	nodeContext := config.SignedContext.Context.Normalized()
	if config.LocalServices != nil && config.LocalServices.Context.CurrentNode != nodeContext.CurrentNode {
		return nil, errors.New("attach: local service identity does not match signed registration")
	}
	if config.ReconnectIdentity != nil {
		if len(config.ReconnectPrivateKey) != ed25519.PrivateKeySize {
			return nil, errors.New("attach: reconnect private key is required with reconnect identity")
		}
		if strings.TrimSpace(config.ReconnectIdentity.Signature) == "" {
			return nil, errors.New("attach: reconnect identity signature is empty")
		}
		if !sameNodeContext(nodeContext, config.ReconnectIdentity.Identity.Context) {
			return nil, errors.New("attach: reconnect identity context does not match signed node context")
		}
		publicKey, keyErr := config.ReconnectIdentity.Identity.PublicKey()
		if keyErr != nil {
			return nil, fmt.Errorf("attach: reconnect identity public key: %w", keyErr)
		}
		privatePublic, ok := config.ReconnectPrivateKey.Public().(ed25519.PublicKey)
		if !ok || !privatePublic.Equal(publicKey) {
			return nil, errors.New("attach: reconnect private key does not match certified public key")
		}
	} else if len(config.ReconnectPrivateKey) != 0 {
		return nil, errors.New("attach: reconnect identity is required with reconnect private key")
	}

	extensions, err := resolveExtensions(config.Extensions)
	if err != nil {
		return nil, fmt.Errorf("attach: %w", err)
	}
	config.Extensions = extensions
	endpoint, err := display.ResolveEnvEndpoint()
	if err != nil {
		return nil, fmt.Errorf("attach: resolve DISPLAY: %w", err)
	}
	cookie := strings.TrimSpace(config.AuthCookie)
	if cookie == "" {
		cookie, err = getSystemX11Cookie()
		if err != nil {
			return nil, fmt.Errorf("attach: resolve X11 cookie: %w", err)
		}
	}
	timeout := config.DialTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dial := config.Dial
	if dial == nil {
		dialer := net.Dialer{Timeout: timeout}
		dial = dialer.DialContext
	}

	peerNode := strings.TrimSpace(config.PreviousNode)
	if peerNode == "" {
		if resolved, _, resolveErr := sessionroute.ResolveNode(nodeContext, "previous"); resolveErr == nil {
			peerNode = resolved
		}
	}
	if peerNode == "" {
		return nil, errors.New("attach: signed topology has no previous peer")
	}

	conn, err := dial(ctx, endpoint.Network, endpoint.Address)
	if err != nil {
		return nil, fmt.Errorf("attach: dial inherited DISPLAY %s: %w", endpoint.String(), err)
	}
	session, err := OpenDynamicSessionConn(ctx, conn, DynamicSessionClientConfig{
		AuthCookie:       cookie,
		Proof:            config.RuntimeProof,
		HandshakeTimeout: timeout,
	})
	if err != nil {
		return nil, err
	}
	var services []sessionmux.ServiceID
	if config.LocalServices != nil {
		services = config.LocalServices.Services()
	}

	var (
		registration sessioncontrol.RegisterResponse
		mode         sessioncontrol.RegistrationMode
		linkID       sessionlink.ID
		transportID  sessionlink.TransportID
	)
	if config.ReconnectIdentity != nil {
		response, challenge, registerErr := sessioncontrol.RegisterNodeReconnect(ctx, session.Mux, sessioncontrol.ReconnectClientConfig{
			Identity:               *config.ReconnectIdentity,
			NodePrivateKey:         config.ReconnectPrivateKey,
			Services:               services,
			ExpectedAcceptorNode:   peerNode,
			ExpectedSessionBinding: session.Binding,
		})
		if registerErr != nil {
			_ = session.Close()
			return nil, fmt.Errorf("attach: reconnect registration: %w", registerErr)
		}
		registration = response
		mode = sessioncontrol.RegistrationModeReconnect
		linkID = challenge.LinkID
		transportID = challenge.TransportID
	} else {
		response, registerErr := sessioncontrol.RegisterNode(ctx, session.Mux, config.SignedContext, services, session.Binding)
		if registerErr != nil {
			_ = session.Close()
			return nil, fmt.Errorf("attach: register node: %w", registerErr)
		}
		registration = response
		mode = sessioncontrol.RegistrationModeLegacy
		linkID, err = sessionlink.DeriveID(sessionlink.Descriptor{
			ChainSHA256: nodeContext.ChainSHA256,
			Topology:    nodeContext.Nodes,
			LocalNode:   nodeContext.CurrentNode,
			PeerNode:    peerNode,
		})
		if err != nil {
			_ = session.Close()
			return nil, fmt.Errorf("attach: derive logical link: %w", err)
		}
		transportID, err = sessionlink.NewTransportID()
		if err != nil {
			_ = session.Close()
			return nil, fmt.Errorf("attach: generate transport id: %w", err)
		}
	}

	leasePath := strings.TrimSpace(config.RouteLeaseStorePath)
	if leasePath == "" {
		leasePath, err = sessionroute.ResolveLeasePath(config.RouteStorePath)
		if err != nil {
			_ = session.Close()
			return nil, fmt.Errorf("attach: resolve route lease store: %w", err)
		}
	}
	router := &sessionroute.Router{
		Store:          sessionroute.Store{Path: config.RouteStorePath},
		LeaseStore:     &sessionroute.LeaseStore{Path: leasePath},
		Context:        nodeContext,
		CurrentBinding: session.Binding,
		CurrentMux:     session.Mux,
		PeerNode:       peerNode,
	}
	if err := runExtensionHook(ctx, config.Extensions, extension.PointSessionReady,
		session.Binding, registration.Node, peerNode, "", 0, nil,
		map[string]string{"role": "attach", "registration": string(mode)}); err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("attach: session-ready extension: %w", err)
	}
	attached := &AttachedSession{
		Session:          session,
		Endpoint:         endpoint,
		Registration:     registration,
		RegistrationMode: mode,
		Node:             registration.Node,
		Context:          nodeContext,
		LinkID:           linkID,
		TransportID:      transportID,
		Local:            config.LocalServices,
		Router:           router,
		serviceDone:      make(chan error, 1),
	}
	apiServer := NewSessionAPIServer(SessionAPIConfig{
		Binding:      session.Binding,
		Context:      nodeContext,
		Local:        config.LocalServices,
		PreviousNode: peerNode,
		HopDepth:     config.HopDepth,
		EncodedWVHop: config.EncodedWVHop,
		Router:       router,
		Extensions:   config.Extensions,
	})
	dispatcher := &sessiondispatch.Dispatcher{
		Mux:     session.Mux,
		Control: apiServer.ServeStream,
		Target: func(dispatchCtx context.Context, stream *sessionmux.Stream) error {
			pending, err := sessioncontrol.InspectAcceptedTarget(stream)
			if err != nil {
				return err
			}
			if err := runExtensionHook(dispatchCtx, config.Extensions, extension.PointTargetOpened,
				session.Binding, registration.Node, peerNode, pending.NodeRef,
				stream.Service(), pending.Data, map[string]string{"role": "attach"}); err != nil {
				_ = stream.Reset()
				return err
			}
			targetNode, _, err := sessionroute.ResolveNode(nodeContext, pending.NodeRef)
			if err != nil {
				_ = stream.Reset()
				return err
			}
			if targetNode == nodeContext.CurrentNode {
				if config.LocalServices == nil {
					_ = stream.Reset()
					return errors.New("attach: no local target service installed")
				}
				accepted, err := sessioncontrol.AuthorizePendingLocal(pending, nodeContext, config.LocalServices.Services())
				if err != nil {
					return err
				}
				if err := runExtensionHook(dispatchCtx, config.Extensions, extension.PointTargetAuthorized,
					session.Binding, registration.Node, peerNode, targetNode,
					stream.Service(), accepted.Data, map[string]string{"role": "attach", "dispatch": "local"}); err != nil {
					_ = stream.Reset()
					return err
				}
				if err := sessioncontrol.AcknowledgePendingTarget(dispatchCtx, pending); err != nil {
					return err
				}
				if !dispatchMapReduce(dispatchCtx, config.LocalServices, accepted) {
					config.LocalServices.Dispatch(dispatchCtx, accepted)
				}
				return nil
			}
			if err := runExtensionHook(dispatchCtx, config.Extensions, extension.PointTargetForwarding,
				session.Binding, registration.Node, peerNode, targetNode,
				stream.Service(), pending.Data, map[string]string{"role": "attach", "dispatch": "forward"}); err != nil {
				_ = stream.Reset()
				return err
			}
			return router.Forward(dispatchCtx, pending)
		},
	}
	go func() {
		serveErr := dispatcher.Serve(ctx)
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		closeErr := runExtensionHook(closeCtx, config.Extensions, extension.PointSessionClosed,
			session.Binding, registration.Node, peerNode, "", 0, nil,
			map[string]string{"role": "attach", "registration": string(mode)})
		cancel()
		if serveErr == nil {
			serveErr = closeErr
		}
		attached.serviceDone <- serveErr
	}()
	return attached, nil
}

func sameNodeContext(left, right authproof.NodeContext) bool {
	leftBytes, leftErr := authproof.CanonicalNodeContextBytes(left)
	rightBytes, rightErr := authproof.CanonicalNodeContextBytes(right)
	return leftErr == nil && rightErr == nil && string(leftBytes) == string(rightBytes)
}
