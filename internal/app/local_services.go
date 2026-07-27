package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/filebackend"
	"weaverssh/internal/p9svc"
	"weaverssh/sessionbind"
	"weaverssh/sessioncontrol"
	"weaverssh/sessionfsops"
	"weaverssh/sessionmux"
	"weaverssh/sessiontcp"
	"weaverssh/sessiontcpproof"
	"weaverssh/sessionudp"
	"weaverssh/sessionudpproof"
	"weaverssh/socksproof"
)

const (
	EnvTCPBindAddress = "WEAVERSSH_TCP_BIND_ADDRESS"
	EnvTCPBindTimeout = "WEAVERSSH_TCP_BIND_TIMEOUT"
)

type LocalServiceConfig struct {
	SignedContext authproof.SignedNodeContext
	PublicKey     ed25519.PublicKey
	MaxTTL        time.Duration

	Root                 string
	ReadOnly             bool
	FileBackend          filebackend.API
	FileCoreStore        filebackend.Store
	FileHooks            *filebackend.Registry

	TCPAllow           sessiontcp.Allowlist
	TCPDial            sessiontcp.DialContextFunc
	TCPProofVerifier   *socksproof.Verifier
	TCPRequireProof    bool
	TCPBindAddress     string
	TCPBindTimeout     time.Duration
	TCPBindListen      sessionbind.ListenFunc
	TCPBindResolvePeer sessionbind.ResolvePeerFunc

	UDPAllow         sessionudp.Allowlist
	UDPProofVerifier *socksproof.Verifier
	UDPListenPacket  sessionudp.ListenPacketFunc
	UDPResolve       sessionudp.ResolveFunc
	UDPReadTimeout   time.Duration
}

type LocalServices struct {
	Context authproof.NodeContext

	services        []sessionmux.ServiceID
	p9              *p9svc.Server
	fsops           *sessionfsops.Server
	fileBackend     filebackend.API
	ownsFileBackend bool
	tcp             *sessiontcp.Server
	tcpProof        *sessiontcpproof.Server
	tcpRequireProof bool
	udp             *sessionudp.Server
	udpProof        *sessionudpproof.Server
}

func NewLocalServices(config LocalServiceConfig) (*LocalServices, error) {
	if len(config.PublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("local services: trusted Ed25519 public key is required")
	}
	if config.MaxTTL <= 0 {
		config.MaxTTL = 10 * time.Minute
	}
	if strings.TrimSpace(config.TCPBindAddress) == "" {
		config.TCPBindAddress = strings.TrimSpace(os.Getenv(EnvTCPBindAddress))
	}
	if config.TCPBindTimeout <= 0 {
		if raw := strings.TrimSpace(os.Getenv(EnvTCPBindTimeout)); raw != "" {
			parsed, err := time.ParseDuration(raw)
			if err != nil || parsed <= 0 {
				return nil, fmt.Errorf("local services: invalid %s %q", EnvTCPBindTimeout, raw)
			}
			config.TCPBindTimeout = parsed
		}
	}
	local, err := authproof.VerifySignedNodeContext(
		config.SignedContext,
		config.PublicKey,
		authproof.NodeContextVerifyOptions{
			Now:         time.Now(),
			Audience:    authproof.AudienceNodeContext,
			CurrentNode: config.SignedContext.Context.CurrentNode,
			MaxTTL:      config.MaxTTL,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("local services: verify node context: %w", err)
	}
	out := &LocalServices{Context: local, tcpRequireProof: config.TCPRequireProof}
	fail := func(err error) (*LocalServices, error) {
		_ = out.Close()
		return nil, err
	}

	if strings.TrimSpace(config.Root) != "" {
		fileService, owned, err := resolveFileBackend(FileBackendConfig{
			Root:             config.Root,
			ReadOnly:         config.ReadOnly,
			Service:          config.FileBackend,
			CoreStore:        config.FileCoreStore,
			Hooks:            config.FileHooks,
		})
		if err != nil {
			return fail(fmt.Errorf("local services: file backend: %w", err))
		}
		out.fileBackend = fileService
		out.ownsFileBackend = owned
		server, err := p9svc.New(p9svc.Config{Root: config.Root, ReadOnly: config.ReadOnly})
		if err != nil {
			return fail(err)
		}
		if err := p9svc.SetBackendAPI(server, fileService); err != nil {
			return fail(err)
		}
		fsops, err := sessionfsops.NewServer(sessionfsops.ServerConfig{
			Root: config.Root, ReadOnly: config.ReadOnly, Backend: fileService,
		})
		if err != nil {
			return fail(err)
		}
		out.p9 = server
		out.fsops = fsops
		out.services = append(out.services, sessionmux.ServiceFS)
	}

	if !config.TCPAllow.Empty() {
		allow := config.TCPAllow
		allowAnyPeer := allow.AllowsAny()
		out.tcp = &sessiontcp.Server{
			DialContext:      config.TCPDial,
			Authorize:        allow.Authorize,
			BindAddress:      strings.TrimSpace(config.TCPBindAddress),
			BindTimeout:      config.TCPBindTimeout,
			BindListen:       config.TCPBindListen,
			BindResolvePeer:  config.TCPBindResolvePeer,
			BindAllowAnyPeer: allowAnyPeer,
		}
		if config.TCPProofVerifier != nil {
			out.tcpProof = &sessiontcpproof.Server{
				DialContext:      config.TCPDial,
				Authorize:        allow.Authorize,
				Verifier:         config.TCPProofVerifier,
				ExpectedNode:     local.CurrentNode,
				BindAddress:      strings.TrimSpace(config.TCPBindAddress),
				BindTimeout:      config.TCPBindTimeout,
				BindListen:       config.TCPBindListen,
				BindResolvePeer:  config.TCPBindResolvePeer,
				BindAllowAnyPeer: allowAnyPeer,
			}
		}
		if config.TCPRequireProof && out.tcpProof == nil {
			return fail(errors.New("local services: TCP proof is required but no verifier is configured"))
		}
		out.services = append(out.services, sessionmux.ServiceTCP)
	}

	if !config.UDPAllow.Empty() {
		allow := config.UDPAllow
		out.udp = &sessionudp.Server{
			Authorize:    allow.Authorize,
			ListenPacket: config.UDPListenPacket,
			Resolve:      config.UDPResolve,
			ReadTimeout:  config.UDPReadTimeout,
		}
		udpVerifier := config.UDPProofVerifier
		if udpVerifier == nil {
			udpVerifier = config.TCPProofVerifier
		}
		if udpVerifier == nil {
			if policyPath := strings.TrimSpace(os.Getenv(EnvSocksProofPolicy)); policyPath != "" {
				loaded, err := LoadSocksProofVerifier(policyPath)
				if err != nil {
					return fail(fmt.Errorf("local services: load UDP proof policy: %w", err))
				}
				udpVerifier = loaded
			}
		}
		if udpVerifier != nil {
			out.udpProof = &sessionudpproof.Server{
				Verifier:        udpVerifier,
				ExpectedNode:    local.CurrentNode,
				Authorize:       allow.Authorize,
				ListenPacket:    config.UDPListenPacket,
				Resolve:         config.UDPResolve,
				ReadTimeout:     config.UDPReadTimeout,
			}
		}
		out.services = append(out.services, sessionmux.ServiceUDP)
	}

	for _, service := range out.services {
		if !localServiceCapability(local, service) {
			return fail(fmt.Errorf("local services: signed context for %s does not authorize %s", local.CurrentNode, service))
		}
	}
	return out, nil
}

func (s *LocalServices) Services() []sessionmux.ServiceID {
	if s == nil { return nil }
	return append([]sessionmux.ServiceID(nil), s.services...)
}
func (s *LocalServices) Empty() bool { return s == nil || len(s.services) == 0 }
func (s *LocalServices) TCPProofEnabled() bool { return s != nil && s.tcpProof != nil }
func (s *LocalServices) TCPProofRequired() bool { return s != nil && s.tcpRequireProof }
func (s *LocalServices) UDPEnabled() bool { return s != nil && s.udp != nil }
func (s *LocalServices) UDPProofEnabled() bool { return s != nil && s.udpProof != nil }

func (s *LocalServices) FileBackendDescription() filebackend.Description {
	if s == nil || s.fileBackend == nil { return filebackend.Description{} }
	return s.fileBackend.Describe()
}
func (s *LocalServices) Close() error {
	if s == nil { return nil }
	uninstallMapReduce(s)
	if !s.ownsFileBackend || s.fileBackend == nil { return nil }
	err := s.fileBackend.Close(); s.fileBackend = nil; s.ownsFileBackend = false; return err
}
func (s *LocalServices) HandleStream(ctx context.Context, stream *sessionmux.Stream) error {
	if s == nil || stream == nil { return errors.New("local services: incomplete accepted stream") }
	accepted, err := sessioncontrol.AuthorizeAcceptedLocal(ctx, stream, s.Context, s.services)
	if err != nil { return err }
	if !dispatchMapReduce(ctx, s, accepted) { s.Dispatch(ctx, accepted) }
	return nil
}
func (s *LocalServices) Serve(ctx context.Context, mux *sessionmux.Mux) error {
	if s == nil || mux == nil { return errors.New("local services: incomplete dispatcher") }
	for { stream, err := mux.Accept(ctx); if err != nil { if ctx.Err()!=nil || errors.Is(err,sessionmux.ErrMuxClosed){return nil};return err }; if err:=s.HandleStream(ctx,stream);err!=nil{_=stream.Reset()} }
}

func (s *LocalServices) Dispatch(ctx context.Context, accepted sessioncontrol.AcceptedTarget) {
	if s == nil || accepted.Stream == nil { return }
	switch accepted.Stream.Service() {
	case sessionmux.ServiceFS:
		switch {
		case len(accepted.Data)==0:
			if s.p9==nil{_=accepted.Stream.Reset();return};go func(){_=s.p9.ServeTransportContext(ctx,accepted.Stream)}()
		case sessionfsops.IsMetadata(accepted.Data):
			if s.fsops==nil{_=accepted.Stream.Reset();return};go func(){_=s.fsops.Serve(ctx,accepted.Stream)}()
		default:_=accepted.Stream.Reset()
		}
	case sessionmux.ServiceTCP:
		switch {
		case sessiontcpproof.IsMetadata(accepted.Data):
			if s.tcpProof==nil{_=accepted.Stream.Reset();return};go func(){_=s.tcpProof.Serve(ctx,accepted.Stream,accepted.Data)}()
		case s.tcpRequireProof:_=accepted.Stream.Reset()
		default:if s.tcp==nil{_=accepted.Stream.Reset();return};go func(){_=s.tcp.Serve(ctx,accepted.Stream,accepted.Data)}()
		}
	case sessionmux.ServiceUDP:
		switch {
		case sessionudpproof.IsMetadata(accepted.Data):
			if s.udpProof==nil{_=accepted.Stream.Reset();return};go func(){_=s.udpProof.Serve(ctx,accepted.Stream,accepted.Data)}()
		case sessionudp.IsMetadata(accepted.Data):
			if s.udp==nil{_=accepted.Stream.Reset();return};go func(){_=s.udp.Serve(ctx,accepted.Stream,accepted.Data)}()
		default:_=accepted.Stream.Reset()
		}
	default:_=accepted.Stream.Reset()
	}
}

func localServiceCapability(ctx authproof.NodeContext, service sessionmux.ServiceID) bool {
	contains:=func(want string)bool{for _,capability:=range ctx.Capabilities{if strings.TrimSpace(capability)==want{return true}};return false}
	switch service {
	case sessionmux.ServiceFS:return contains(authproof.CapabilityVFSMesh)||contains(authproof.CapabilityFileBackhaul)
	case sessionmux.ServiceTCP,sessionmux.ServiceUDP:return contains(authproof.CapabilitySocksProxy)
	default:return false
	}
}
