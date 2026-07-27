package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/extension"
	"weaverssh/sessioncontrol"
	"weaverssh/sessiondispatch"
	"weaverssh/sessionlink"
	"weaverssh/sessionmux"
	"weaverssh/sessionroute"
	"weaverssh/sessionruntime"
)

type HostSessionGeneration struct {
	Session          *sessionruntime.Session
	Registry         *sessioncontrol.Registry
	Local            sessioncontrol.Node
	Remote           sessioncontrol.Node
	Router           *sessionroute.Router
	RegistrationMode sessioncontrol.RegistrationMode
	LinkID           sessionlink.ID
	TransportID      sessionlink.TransportID
}

type HostGenerationReadyFunc func(HostSessionGeneration) (func(error), error)

type DynamicHostReconnectConfig struct {
	ExpectedPeerNode    string
	ChallengeTTL        time.Duration
	MaxIdentityTTL      time.Duration
	RouteLeaseStorePath string
	ReplayCache         *authproof.NonceCache
	OnReady             HostGenerationReadyFunc
}

func (h *DynamicHost) ServeReconnectable(ctx context.Context, session *sessionruntime.Session, authority DynamicSessionContext, config DynamicHostReconnectConfig) error {
	if h == nil || h.local == nil || session == nil || session.Mux == nil {
		return errors.New("dynamic host: incomplete session")
	}
	peerNode := strings.TrimSpace(config.ExpectedPeerNode)
	if peerNode == "" {
		resolved, _, err := sessionroute.ResolveNode(h.local.Context, "next")
		if err != nil {
			return fmt.Errorf("dynamic host: resolve reconnect peer: %w", err)
		}
		peerNode = resolved
	}
	transportID, err := sessionlink.NewTransportID()
	if err != nil {
		return fmt.Errorf("dynamic host: generate transport id: %w", err)
	}
	registry := sessioncontrol.NewRegistry()
	localNode, err := registry.RegisterVerified(h.local.Context, h.local.Services())
	if err != nil {
		return fmt.Errorf("dynamic host: register local node: %w", err)
	}
	legacyVerifier := sessioncontrol.NewAuthproofVerifier(h.config.PublicKey, authproof.NodeContextVerifyOptions{
		Audience: authproof.AudienceNodeContext, ChainID: h.local.Context.ChainID,
		ChainSHA256: h.local.Context.ChainSHA256, MaxTTL: h.config.MaxTTL, ReplayCache: h.replay,
	})
	if config.MaxIdentityTTL <= 0 {
		config.MaxIdentityTTL = 24 * time.Hour
	}
	if config.ReplayCache == nil {
		config.ReplayCache = authproof.NewNonceCache()
	}
	accepted, err := sessioncontrol.ServeAnyRegistration(ctx, session.Mux, registry, sessioncontrol.AnyRegistrationConfig{
		LegacyVerifier: legacyVerifier, ExpectedSessionBinding: authority.Binding,
		Reconnect: &sessioncontrol.ReconnectServerConfig{
			AuthorityPublicKey: h.config.PublicKey, LocalContext: h.local.Context, PeerNode: peerNode,
			SessionBinding: authority.Binding, TransportID: transportID, ChallengeTTL: config.ChallengeTTL,
			MaxIdentityTTL: config.MaxIdentityTTL, ReplayCache: config.ReplayCache,
		},
	})
	if err != nil {
		return fmt.Errorf("dynamic host: remote registration: %w", err)
	}
	remoteNode := accepted.Node
	if remoteNode.ID != peerNode {
		return fmt.Errorf("dynamic host: registered peer %q does not match expected adjacent node %q", remoteNode.ID, peerNode)
	}
	linkID, err := sessionlink.DeriveID(sessionlink.Descriptor{
		ChainSHA256: h.local.Context.ChainSHA256, Topology: h.local.Context.Nodes,
		LocalNode: h.local.Context.CurrentNode, PeerNode: remoteNode.ID,
	})
	if err != nil {
		return fmt.Errorf("dynamic host: derive logical link: %w", err)
	}
	if accepted.Mode == sessioncontrol.RegistrationModeReconnect {
		if accepted.LinkID != linkID || accepted.TransportID != transportID || accepted.SessionBinding != session.Binding {
			return errors.New("dynamic host: reconnect registration transport identity mismatch")
		}
	}
	leasePath := strings.TrimSpace(config.RouteLeaseStorePath)
	if leasePath == "" {
		leasePath, err = sessionroute.ResolveLeasePath(h.config.RouteStorePath)
		if err != nil {
			return fmt.Errorf("dynamic host: resolve route lease store: %w", err)
		}
	}
	router := &sessionroute.Router{
		Store: sessionroute.Store{Path: h.config.RouteStorePath}, LeaseStore: &sessionroute.LeaseStore{Path: leasePath},
		Context: h.local.Context, CurrentBinding: session.Binding, CurrentMux: session.Mux, PeerNode: remoteNode.ID,
	}
	if err := runExtensionHook(ctx, h.config.Extensions, extension.PointSessionReady,
		session.Binding, localNode.ID, remoteNode.ID, "", 0, nil,
		map[string]string{"role": "host", "registration": string(accepted.Mode)}); err != nil {
		return fmt.Errorf("dynamic host: session-ready extension: %w", err)
	}
	var cleanup func(error)
	if config.OnReady != nil {
		cleanup, err = config.OnReady(HostSessionGeneration{
			Session: session, Registry: registry, Local: localNode, Remote: remoteNode, Router: router,
			RegistrationMode: accepted.Mode, LinkID: linkID, TransportID: transportID,
		})
		if err != nil {
			return fmt.Errorf("dynamic host: ready lifecycle: %w", err)
		}
	}
	apiServer := NewSessionAPIServer(SessionAPIConfig{
		Binding: session.Binding, Context: h.local.Context, Local: h.local, Registry: registry,
		PreviousNode: h.config.PreviousNode, HopDepth: h.config.HopDepth, EncodedWVHop: h.config.EncodedWVHop,
		Router: router, Extensions: h.config.Extensions,
	})
	dispatcher := &sessiondispatch.Dispatcher{
		Mux: session.Mux, Control: apiServer.ServeStream,
		Target: func(dispatchCtx context.Context, stream *sessionmux.Stream) error {
			pending, err := sessioncontrol.InspectAcceptedTarget(stream)
			if err != nil {
				return err
			}
			if err := runExtensionHook(dispatchCtx, h.config.Extensions, extension.PointTargetOpened,
				session.Binding, localNode.ID, remoteNode.ID, pending.NodeRef,
				stream.Service(), pending.Data, map[string]string{"role": "host"}); err != nil {
				_ = stream.Reset()
				return err
			}
			targetNode, _, err := sessionroute.ResolveNode(h.local.Context, pending.NodeRef)
			if err != nil {
				_ = stream.Reset()
				return err
			}
			if targetNode == localNode.ID {
				acceptedTarget, err := sessioncontrol.AuthorizePendingLocal(pending, h.local.Context, h.local.Services())
				if err != nil {
					return err
				}
				if err := runExtensionHook(dispatchCtx, h.config.Extensions, extension.PointTargetAuthorized,
					session.Binding, localNode.ID, remoteNode.ID, targetNode,
					stream.Service(), acceptedTarget.Data, map[string]string{"role": "host", "dispatch": "local"}); err != nil {
					_ = stream.Reset()
					return err
				}
				if err := sessioncontrol.AcknowledgePendingTarget(dispatchCtx, pending); err != nil {
					return err
				}
				if !dispatchMapReduce(dispatchCtx, h.local, acceptedTarget) {
					h.local.Dispatch(dispatchCtx, acceptedTarget)
				}
				return nil
			}
			if err := runExtensionHook(dispatchCtx, h.config.Extensions, extension.PointTargetForwarding,
				session.Binding, localNode.ID, remoteNode.ID, targetNode,
				stream.Service(), pending.Data, map[string]string{"role": "host", "dispatch": "forward"}); err != nil {
				_ = stream.Reset()
				return err
			}
			return router.Forward(dispatchCtx, pending)
		},
	}
	serveErr := dispatcher.Serve(ctx)
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	closeErr := runExtensionHook(closeCtx, h.config.Extensions, extension.PointSessionClosed,
		session.Binding, localNode.ID, remoteNode.ID, "", 0, nil,
		map[string]string{"role": "host", "registration": string(accepted.Mode)})
	cancel()
	terminal := serveErr
	if terminal == nil {
		terminal = closeErr
	}
	if cleanup != nil {
		cleanup(terminal)
	}
	return terminal
}
