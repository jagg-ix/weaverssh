package app

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/extension"
	"weaverssh/filebackend"
	"weaverssh/sessioncontrol"
	"weaverssh/sessiondispatch"
	"weaverssh/sessionmux"
	"weaverssh/sessionroute"
	"weaverssh/sessionruntime"
	"weaverssh/sessiontcp"
	"weaverssh/sessionudp"
	"weaverssh/socksproof"
)

type HostSessionReadyFunc func(
	*sessionruntime.Session,
	*sessioncontrol.Registry,
	sessioncontrol.Node,
	sessioncontrol.Node,
	*sessionroute.Router,
) (func(), error)

type DynamicHostConfig struct {
	Root                 string
	ReadOnly             bool
	FileBackend          filebackend.API
	FileCoreStore        filebackend.Store
	FileHooks            *filebackend.Registry
	SignedContext        authproof.SignedNodeContext
	PublicKey            ed25519.PublicKey
	MaxTTL               time.Duration
	TCPAllow             sessiontcp.Allowlist
	TCPDial              sessiontcp.DialContextFunc
	TCPProofVerifier     *socksproof.Verifier
	TCPRequireProof      bool
	UDPAllow             sessionudp.Allowlist
	UDPListenPacket      sessionudp.ListenPacketFunc
	UDPResolve           sessionudp.ResolveFunc
	UDPReadTimeout       time.Duration
	Extensions           *extension.Registry
	OnReady              HostSessionReadyFunc
	ControlOnly          bool
	PreviousNode         string
	HopDepth             int
	EncodedWVHop         string
	RouteStorePath       string
}

type DynamicHost struct {
	config DynamicHostConfig
	local  *LocalServices
	replay *authproof.NonceCache
}

func NewDynamicHost(config DynamicHostConfig) (*DynamicHost, error) {
	if strings.TrimSpace(config.Root) == "" &&
		config.TCPAllow.Empty() &&
		config.UDPAllow.Empty() &&
		!config.ControlOnly &&
		!mapReduceEnvironmentConfigured() {
		return nil, errors.New("dynamic host: at least one local fs, tcp, udp, or mapreduce service is required unless control-only mode is enabled")
	}
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("dynamic host: trusted Ed25519 public key is required")
	}
	if config.MaxTTL <= 0 {
		config.MaxTTL = 10 * time.Minute
	}
	extensions, err := resolveExtensions(config.Extensions)
	if err != nil {
		return nil, fmt.Errorf("dynamic host: %w", err)
	}
	config.Extensions = extensions
	if config.TCPProofVerifier == nil {
		if policyPath := strings.TrimSpace(os.Getenv(EnvSocksProofPolicy)); policyPath != "" {
			verifier, err := LoadSocksProofVerifier(policyPath)
			if err != nil {
				return nil, fmt.Errorf("dynamic host: load SOCKS proof policy: %w", err)
			}
			config.TCPProofVerifier = verifier
		}
	}
	if !config.TCPRequireProof {
		config.TCPRequireProof = envBoolValue(os.Getenv(EnvTCPRequireProof))
	}
	local, err := NewLocalServices(LocalServiceConfig{
		SignedContext:        config.SignedContext,
		PublicKey:            config.PublicKey,
		MaxTTL:               config.MaxTTL,
		Root:                 config.Root,
		ReadOnly:             config.ReadOnly,
		FileBackend:          config.FileBackend,
		FileCoreStore:        config.FileCoreStore,
		FileHooks:            config.FileHooks,
		TCPAllow:             config.TCPAllow,
		TCPDial:              config.TCPDial,
		TCPProofVerifier:     config.TCPProofVerifier,
		TCPRequireProof:      config.TCPRequireProof,
		UDPAllow:             config.UDPAllow,
		UDPListenPacket:      config.UDPListenPacket,
		UDPResolve:           config.UDPResolve,
		UDPReadTimeout:       config.UDPReadTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("dynamic host: %w", err)
	}
	if err := installConfiguredMapReduce(local); err != nil {
		_ = local.Close()
		return nil, fmt.Errorf("dynamic host: %w", err)
	}
	if config.ControlOnly && !local.Empty() {
		uninstallMapReduce(local)
		_ = local.Close()
		return nil, errors.New("dynamic host: control-only mode cannot advertise local services")
	}
	return &DynamicHost{config: config, local: local, replay: authproof.NewNonceCache()}, nil
}

func (h *DynamicHost) Close() error {
	if h == nil || h.local == nil {
		return nil
	}
	uninstallMapReduce(h.local)
	return h.local.Close()
}

func (h *DynamicHost) Serve(ctx context.Context, session *sessionruntime.Session, authority DynamicSessionContext) error {
	if h == nil || h.local == nil || session == nil || session.Mux == nil {
		return errors.New("dynamic host: incomplete session")
	}
	registry := sessioncontrol.NewRegistry()
	localNode, err := registry.RegisterVerified(h.local.Context, h.local.Services())
	if err != nil {
		return fmt.Errorf("dynamic host: register local node: %w", err)
	}
	verifier := sessioncontrol.NewAuthproofVerifier(h.config.PublicKey, authproof.NodeContextVerifyOptions{
		Audience:    authproof.AudienceNodeContext,
		ChainID:     h.local.Context.ChainID,
		ChainSHA256: h.local.Context.ChainSHA256,
		MaxTTL:      h.config.MaxTTL,
		ReplayCache: h.replay,
	})
	remoteNode, err := sessioncontrol.ServeRegistration(ctx, session.Mux, registry, verifier, authority.Binding)
	if err != nil {
		return fmt.Errorf("dynamic host: remote registration: %w", err)
	}
	router := &sessionroute.Router{
		Store:          sessionroute.Store{Path: h.config.RouteStorePath},
		Context:        h.local.Context,
		CurrentBinding: session.Binding,
		CurrentMux:     session.Mux,
		PeerNode:       remoteNode.ID,
	}
	if err := runExtensionHook(ctx, h.config.Extensions, extension.PointSessionReady,
		session.Binding, localNode.ID, remoteNode.ID, "", 0, nil,
		map[string]string{"role": "host"}); err != nil {
		return fmt.Errorf("dynamic host: session-ready extension: %w", err)
	}
	if h.config.OnReady != nil {
		cleanup, readyErr := h.config.OnReady(session, registry, localNode, remoteNode, router)
		if readyErr != nil {
			return fmt.Errorf("dynamic host: ready lifecycle: %w", readyErr)
		}
		if cleanup != nil {
			defer cleanup()
		}
	}
	apiServer := NewSessionAPIServer(SessionAPIConfig{
		Binding:      session.Binding,
		Context:      h.local.Context,
		Local:        h.local,
		Registry:     registry,
		PreviousNode: h.config.PreviousNode,
		HopDepth:     h.config.HopDepth,
		EncodedWVHop: h.config.EncodedWVHop,
		Router:       router,
		Extensions:   h.config.Extensions,
	})
	dispatcher := &sessiondispatch.Dispatcher{
		Mux:     session.Mux,
		Control: apiServer.ServeStream,
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
				accepted, err := sessioncontrol.AuthorizePendingLocal(pending, h.local.Context, h.local.Services())
				if err != nil {
					return err
				}
				if err := runExtensionHook(dispatchCtx, h.config.Extensions, extension.PointTargetAuthorized,
					session.Binding, localNode.ID, remoteNode.ID, targetNode,
					stream.Service(), accepted.Data, map[string]string{"role": "host", "dispatch": "local"}); err != nil {
					_ = stream.Reset()
					return err
				}
				if err := sessioncontrol.AcknowledgePendingTarget(dispatchCtx, pending); err != nil {
					return err
				}
				if !dispatchMapReduce(dispatchCtx, h.local, accepted) {
					h.local.Dispatch(dispatchCtx, accepted)
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
		map[string]string{"role": "host"})
	cancel()
	if serveErr != nil {
		return serveErr
	}
	if closeErr != nil {
		return fmt.Errorf("dynamic host: session-closed extension: %w", closeErr)
	}
	return nil
}

func LoadSignedNodeContextFile(path string) (authproof.SignedNodeContext, error) {
	var signed authproof.SignedNodeContext
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return signed, err
	}
	if err := json.Unmarshal(data, &signed); err != nil {
		return signed, err
	}
	return signed, nil
}

func LoadSignedGrantFile(path string) (authproof.SignedGrant, error) {
	var signed authproof.SignedGrant
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return signed, err
	}
	if err := json.Unmarshal(data, &signed); err != nil {
		return signed, err
	}
	return signed, nil
}

func LoadEd25519PublicKeyFile(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil, err
	}
	return authproof.DecodePublicKey(strings.TrimSpace(string(data)))
}
