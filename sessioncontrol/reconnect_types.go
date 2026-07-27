package sessioncontrol

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionlink"
	"weaverssh/sessionmux"
)

const (
	ReconnectProtocolVersion  = "weaverssh.session-control.reconnect.v1"
	ReconnectChallengeVersion = "weaverssh.reconnect-challenge.v1"
	ReconnectStatementVersion = "weaverssh.reconnect-statement.v1"
	MaxReconnectChallengeTTL  = 2 * time.Minute
	maxReconnectMessageBytes  = 128 << 10

	reconnectChallengeType = "node.reconnect.challenge"
	reconnectProofType     = "node.reconnect.prove"
	reconnectAcceptedType  = "node.reconnected"
)

var (
	ErrReconnectProtocol  = errors.New("sessioncontrol: invalid reconnect protocol")
	ErrReconnectChallenge = errors.New("sessioncontrol: invalid reconnect challenge")
	ErrReconnectProof     = errors.New("sessioncontrol: invalid reconnect proof")
)

type ReconnectChallenge struct {
	Version        string                  `json:"version"`
	Algorithm      string                  `json:"algorithm"`
	ChallengeID    string                  `json:"challenge_id"`
	LinkID         sessionlink.ID          `json:"link_id"`
	TransportID    sessionlink.TransportID `json:"transport_id"`
	SessionBinding string                  `json:"session_binding"`
	ChainSHA256    string                  `json:"chain_sha256"`
	AcceptorNode   string                  `json:"acceptor_node"`
	ProverNode     string                  `json:"prover_node"`
	IssuedAtUnix   int64                   `json:"issued_at_unix"`
	ExpiresAtUnix  int64                   `json:"expires_at_unix"`
}

type ReconnectStatement struct {
	Version         string                  `json:"version"`
	Algorithm       string                  `json:"algorithm"`
	ChallengeSHA256 string                  `json:"challenge_sha256"`
	IdentitySHA256  string                  `json:"identity_sha256"`
	LinkID          sessionlink.ID          `json:"link_id"`
	TransportID     sessionlink.TransportID `json:"transport_id"`
	SessionBinding  string                  `json:"session_binding"`
	ChainSHA256     string                  `json:"chain_sha256"`
	AcceptorNode    string                  `json:"acceptor_node"`
	ProverNode      string                  `json:"prover_node"`
	Services        []sessionmux.ServiceID  `json:"services"`
}

type ReconnectProof struct {
	Statement ReconnectStatement `json:"statement"`
	Signature string             `json:"signature"`
}

type ReconnectChallengeEnvelope struct {
	Type      string             `json:"type"`
	Protocol  string             `json:"protocol"`
	Challenge ReconnectChallenge `json:"challenge"`
}

type ReconnectProofEnvelope struct {
	Type     string                            `json:"type"`
	Protocol string                            `json:"protocol"`
	Identity authproof.SignedReconnectIdentity `json:"identity"`
	Proof    ReconnectProof                    `json:"proof"`
}

type ReconnectAccepted struct {
	Node           Node
	Identity       authproof.ReconnectIdentity
	LinkID         sessionlink.ID
	TransportID    sessionlink.TransportID
	SessionBinding string
	Services       []sessionmux.ServiceID
}

type ReconnectServerConfig struct {
	AuthorityPublicKey ed25519.PublicKey
	LocalContext       authproof.NodeContext
	PeerNode           string
	SessionBinding     string
	TransportID        sessionlink.TransportID
	ChallengeTTL       time.Duration
	MaxIdentityTTL     time.Duration
	ReplayCache        *authproof.NonceCache
	Now                func() time.Time
}

type ReconnectClientConfig struct {
	Identity               authproof.SignedReconnectIdentity
	NodePrivateKey         ed25519.PrivateKey
	Services               []sessionmux.ServiceID
	ExpectedAcceptorNode   string
	ExpectedSessionBinding string
	ExpectedTransportID    sessionlink.TransportID
	Now                    func() time.Time
}

func (c ReconnectChallenge) Normalized() ReconnectChallenge {
	out := c
	if out.Version == "" {
		out.Version = ReconnectChallengeVersion
	}
	if out.Algorithm == "" {
		out.Algorithm = authproof.Algorithm
	}
	out.Version = strings.TrimSpace(out.Version)
	out.Algorithm = strings.TrimSpace(out.Algorithm)
	out.ChallengeID = strings.TrimSpace(out.ChallengeID)
	out.TransportID = sessionlink.TransportID(strings.TrimSpace(string(out.TransportID)))
	out.SessionBinding = strings.TrimSpace(out.SessionBinding)
	out.ChainSHA256 = strings.ToLower(strings.TrimSpace(out.ChainSHA256))
	out.AcceptorNode = strings.TrimSpace(out.AcceptorNode)
	out.ProverNode = strings.TrimSpace(out.ProverNode)
	return out
}

func (s ReconnectStatement) Normalized() ReconnectStatement {
	out := s
	if out.Version == "" {
		out.Version = ReconnectStatementVersion
	}
	if out.Algorithm == "" {
		out.Algorithm = authproof.Algorithm
	}
	out.Version = strings.TrimSpace(out.Version)
	out.Algorithm = strings.TrimSpace(out.Algorithm)
	out.ChallengeSHA256 = strings.ToLower(strings.TrimSpace(out.ChallengeSHA256))
	out.IdentitySHA256 = strings.ToLower(strings.TrimSpace(out.IdentitySHA256))
	out.TransportID = sessionlink.TransportID(strings.TrimSpace(string(out.TransportID)))
	out.SessionBinding = strings.TrimSpace(out.SessionBinding)
	out.ChainSHA256 = strings.ToLower(strings.TrimSpace(out.ChainSHA256))
	out.AcceptorNode = strings.TrimSpace(out.AcceptorNode)
	out.ProverNode = strings.TrimSpace(out.ProverNode)
	normalized, _ := normalizeReconnectServices(out.Services)
	out.Services = normalized
	return out
}
