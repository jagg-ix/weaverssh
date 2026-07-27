package socksproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"weaverssh/authproof"
)

const (
	CommandConnect      = byte(0x01)
	CommandBind         = byte(0x02)
	CommandUDPAssociate = byte(0x03)

	CapabilityBind         = "socks.bind"
	CapabilityUDPAssociate = "socks.udp-associate"

	maxDatagramMetadataBytes = 12 << 10
	maxProofDatagramBytes    = 65507
)

type DatagramStatement struct {
	Protocol        string `json:"protocol"`
	Principal       string `json:"principal"`
	ChallengeSHA256 string `json:"challenge_sha256"`
	IdentitySHA256  string `json:"identity_sha256"`
	Command         byte   `json:"command"`
	Network         string `json:"network"`
	Address         string `json:"address"`
	SessionBinding  string `json:"session_binding"`
	SelectedNode    string `json:"selected_node"`
	Sequence        uint64 `json:"sequence"`
	PayloadSHA256   string `json:"payload_sha256"`
	Nonce           string `json:"nonce"`
	IssuedAtUnix    int64  `json:"issued_at_unix"`
	ExpiresAtUnix   int64  `json:"expires_at_unix"`
}

type SignedDatagram struct {
	Statement DatagramStatement `json:"statement"`
	Signature string            `json:"signature"`
}

func SignCommand(challenge Challenge, identity SignedIdentity, command byte, network, address string, signer Signer, ttl time.Duration, now time.Time) (SignedConnect, error) {
	if signer == nil {
		return SignedConnect{}, errors.New("socksproof: signer required")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(challenge, now); err != nil {
		return SignedConnect{}, err
	}
	if strings.TrimSpace(identity.Statement.Principal) == "" || identity.Statement.ChallengeSHA256 != DigestChallenge(challenge) || strings.TrimSpace(identity.Signature) == "" {
		return SignedConnect{}, ErrInvalidProof
	}
	allowZero := command == CommandUDPAssociate || command == CommandBind
	network, address, err := normalizeCommandAddress(command, network, address, allowZero)
	if err != nil {
		return SignedConnect{}, err
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	expires := boundedExpiry(now, ttl, challenge.ExpiresAtUnix)
	if expires <= now.Unix() {
		return SignedConnect{}, ErrExpired
	}
	nonce, err := randomNonce(24)
	if err != nil {
		return SignedConnect{}, err
	}
	statement := ConnectStatement{
		Protocol: ProtocolVersion, Principal: identity.Statement.Principal,
		ChallengeSHA256: DigestChallenge(challenge), IdentitySHA256: DigestIdentity(identity),
		Command: command, Network: network, Address: address,
		SessionBinding: challenge.SessionBinding, SelectedNode: challenge.SelectedNode,
		Nonce: nonce, IssuedAtUnix: now.Unix(), ExpiresAtUnix: expires,
	}
	payload, err := canonical(statement)
	if err != nil {
		return SignedConnect{}, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return SignedConnect{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedConnect{}, authproof.ErrInvalidSignature
	}
	return SignedConnect{Statement: statement, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func SignBind(challenge Challenge, identity SignedIdentity, network, address string, signer Signer, ttl time.Duration, now time.Time) (SignedConnect, error) {
	return SignCommand(challenge, identity, CommandBind, network, address, signer, ttl, now)
}

func SignUDPAssociate(challenge Challenge, identity SignedIdentity, network, address string, signer Signer, ttl time.Duration, now time.Time) (SignedConnect, error) {
	return SignCommand(challenge, identity, CommandUDPAssociate, network, address, signer, ttl, now)
}

func (v *Verifier) VerifyCommand(challenge Challenge, identity SignedIdentity, proof SignedConnect, command byte, expectedNetwork, expectedAddress, expectedBinding, expectedNode string, now time.Time) (PrincipalPolicy, error) {
	if v == nil {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(challenge, now); err != nil {
		return PrincipalPolicy{}, err
	}
	if challenge.ServerID != v.ServerID || challenge.PolicySHA256 != v.PolicySHA256 {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	allowZero := command == CommandUDPAssociate || command == CommandBind
	network, address, err := normalizeCommandAddress(command, expectedNetwork, expectedAddress, allowZero)
	if err != nil {
		return PrincipalPolicy{}, err
	}
	expectedBinding = strings.TrimSpace(expectedBinding)
	expectedNode = strings.TrimSpace(expectedNode)
	if expectedBinding == "" || expectedNode == "" {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	statement := proof.Statement
	if statement.Protocol != ProtocolVersion || statement.Command != command || strings.TrimSpace(statement.Principal) == "" || strings.TrimSpace(statement.Nonce) == "" || strings.TrimSpace(proof.Signature) == "" {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.Principal != identity.Statement.Principal || statement.ChallengeSHA256 != DigestChallenge(challenge) || statement.IdentitySHA256 != DigestIdentity(identity) {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.Network != network || statement.Address != address || statement.SessionBinding != expectedBinding || statement.SelectedNode != expectedNode {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.IssuedAtUnix < identity.Statement.IssuedAtUnix || statement.ExpiresAtUnix > identity.Statement.ExpiresAtUnix || statement.ExpiresAtUnix > challenge.ExpiresAtUnix {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	principal, ok := v.principals[strings.TrimSpace(statement.Principal)]
	if !ok {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	if err := ValidateTime(statement.IssuedAtUnix, statement.ExpiresAtUnix, principal.maxTTL, now); err != nil {
		return PrincipalPolicy{}, err
	}
	if err := VerifySignature(principal.key, statement, proof.Signature); err != nil {
		return PrincipalPolicy{}, err
	}
	capability := capabilityForCommand(command)
	if capability == "" || !contains(identity.Statement.Capabilities, capability) || !contains(principal.policy.Capabilities, capability) {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	switch {
	case command == CommandUDPAssociate && wildcardEndpoint(address):
		// The requested address identifies the client-side UDP endpoint. Actual
		// destination authorization is performed for every signed datagram.
	case command == CommandBind && wildcardEndpoint(address):
		if !principal.allow.AllowsAny() {
			return PrincipalPolicy{}, fmt.Errorf("%w: wildcard BIND requires explicit *:* policy", ErrUnauthorized)
		}
	default:
		if err := principal.allow.Authorize(address); err != nil {
			return PrincipalPolicy{}, err
		}
	}
	if err := v.connectReplay.Check(statement.Nonce, statement.ExpiresAtUnix, now); err != nil {
		return PrincipalPolicy{}, err
	}
	return principal.policy, nil
}

func (c ServerConfig) VerifyCommand(session ServerSession, proof SignedConnect, command byte, network, address string, now time.Time) error {
	if c.Verifier == nil {
		return ErrUnauthorized
	}
	_, err := c.Verifier.VerifyCommand(session.Challenge, session.Identity, proof, command, network, address, c.SessionBinding, c.SelectedNode, now)
	return err
}

func SignDatagram(challenge Challenge, identity SignedIdentity, sequence uint64, network, address string, packet []byte, signer Signer, ttl time.Duration, now time.Time) (SignedDatagram, error) {
	if signer == nil || len(packet) == 0 || len(packet) > maxProofDatagramBytes {
		return SignedDatagram{}, ErrInvalidProof
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(challenge, now); err != nil {
		return SignedDatagram{}, err
	}
	network, address, err := normalizeCommandAddress(CommandUDPAssociate, network, address, false)
	if err != nil {
		return SignedDatagram{}, err
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	expires := boundedExpiry(now, ttl, challenge.ExpiresAtUnix)
	if expires <= now.Unix() {
		return SignedDatagram{}, ErrExpired
	}
	nonce, err := randomNonce(24)
	if err != nil {
		return SignedDatagram{}, err
	}
	sum := sha256.Sum256(packet)
	statement := DatagramStatement{
		Protocol: ProtocolVersion, Principal: identity.Statement.Principal,
		ChallengeSHA256: DigestChallenge(challenge), IdentitySHA256: DigestIdentity(identity),
		Command: CommandUDPAssociate, Network: network, Address: address,
		SessionBinding: challenge.SessionBinding, SelectedNode: challenge.SelectedNode,
		Sequence: sequence, PayloadSHA256: hex.EncodeToString(sum[:]), Nonce: nonce,
		IssuedAtUnix: now.Unix(), ExpiresAtUnix: expires,
	}
	payload, err := canonical(statement)
	if err != nil {
		return SignedDatagram{}, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return SignedDatagram{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedDatagram{}, authproof.ErrInvalidSignature
	}
	return SignedDatagram{Statement: statement, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func (v *Verifier) VerifyDatagram(session ServerSession, proof SignedDatagram, packet []byte, expectedNetwork, expectedAddress, expectedBinding, expectedNode string, now time.Time) (PrincipalPolicy, error) {
	if v == nil || len(packet) == 0 || len(packet) > maxProofDatagramBytes {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(session.Challenge, now); err != nil {
		return PrincipalPolicy{}, err
	}
	network, address, err := normalizeCommandAddress(CommandUDPAssociate, expectedNetwork, expectedAddress, false)
	if err != nil {
		return PrincipalPolicy{}, err
	}
	statement := proof.Statement
	if statement.Protocol != ProtocolVersion || statement.Command != CommandUDPAssociate || statement.Principal != session.Identity.Statement.Principal || statement.ChallengeSHA256 != DigestChallenge(session.Challenge) || statement.IdentitySHA256 != DigestIdentity(session.Identity) {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.Network != network || statement.Address != address || statement.SessionBinding != strings.TrimSpace(expectedBinding) || statement.SelectedNode != strings.TrimSpace(expectedNode) {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	if statement.IssuedAtUnix < session.Identity.Statement.IssuedAtUnix || statement.ExpiresAtUnix > session.Identity.Statement.ExpiresAtUnix || statement.ExpiresAtUnix > session.Challenge.ExpiresAtUnix {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	sum := sha256.Sum256(packet)
	if statement.PayloadSHA256 != hex.EncodeToString(sum[:]) {
		return PrincipalPolicy{}, ErrInvalidProof
	}
	principal, ok := v.principals[strings.TrimSpace(statement.Principal)]
	if !ok || !contains(session.Identity.Statement.Capabilities, CapabilityUDPAssociate) || !contains(principal.policy.Capabilities, CapabilityUDPAssociate) {
		return PrincipalPolicy{}, ErrUnauthorized
	}
	if err := ValidateTime(statement.IssuedAtUnix, statement.ExpiresAtUnix, principal.maxTTL, now); err != nil {
		return PrincipalPolicy{}, err
	}
	if err := VerifySignature(principal.key, statement, proof.Signature); err != nil {
		return PrincipalPolicy{}, err
	}
	if err := principal.allow.Authorize(address); err != nil {
		return PrincipalPolicy{}, err
	}
	if err := v.connectReplay.Check(statement.Nonce, statement.ExpiresAtUnix, now); err != nil {
		return PrincipalPolicy{}, err
	}
	return principal.policy, nil
}

func (c ServerConfig) VerifyDatagram(session ServerSession, proof SignedDatagram, packet []byte, network, address string, now time.Time) error {
	if c.Verifier == nil {
		return ErrUnauthorized
	}
	_, err := c.Verifier.VerifyDatagram(session, proof, packet, network, address, c.SessionBinding, c.SelectedNode, now)
	return err
}

func EncodeDatagramEnvelope(proof SignedDatagram, packet []byte) ([]byte, error) {
	metadata, err := json.Marshal(proof)
	if err != nil {
		return nil, err
	}
	if len(metadata) == 0 || len(metadata) > maxDatagramMetadataBytes || len(packet) == 0 || 4+len(metadata)+len(packet) > maxProofDatagramBytes {
		return nil, ErrInvalidProof
	}
	out := make([]byte, 4+len(metadata)+len(packet))
	binary.BigEndian.PutUint32(out[:4], uint32(len(metadata)))
	copy(out[4:], metadata)
	copy(out[4+len(metadata):], packet)
	return out, nil
}

func DecodeDatagramEnvelope(raw []byte) (SignedDatagram, []byte, error) {
	if len(raw) < 5 || len(raw) > maxProofDatagramBytes {
		return SignedDatagram{}, nil, ErrInvalidProof
	}
	metadataLength := int(binary.BigEndian.Uint32(raw[:4]))
	if metadataLength <= 0 || metadataLength > maxDatagramMetadataBytes || 4+metadataLength >= len(raw) {
		return SignedDatagram{}, nil, ErrInvalidProof
	}
	var proof SignedDatagram
	decoder := json.NewDecoder(bytes.NewReader(raw[4 : 4+metadataLength]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return SignedDatagram{}, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return SignedDatagram{}, nil, errors.New("socksproof: trailing datagram metadata")
	}
	packet := append([]byte(nil), raw[4+metadataLength:]...)
	return proof, packet, nil
}

func normalizeCommandAddress(command byte, network, address string, allowZeroPort bool) (string, string, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	switch command {
	case CommandConnect, CommandBind:
		if network == "" {
			network = "tcp"
		}
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return "", "", fmt.Errorf("socksproof: unsupported network %q", network)
		}
	case CommandUDPAssociate:
		if network == "" {
			network = "udp"
		}
		if network != "udp" && network != "udp4" && network != "udp6" {
			return "", "", fmt.Errorf("socksproof: unsupported network %q", network)
		}
	default:
		return "", "", ErrInvalidProof
	}
	host, portText, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || strings.TrimSpace(host) == "" {
		return "", "", ErrInvalidProof
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 || (!allowZeroPort && port == 0) {
		return "", "", ErrInvalidProof
	}
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" || strings.IndexByte(host, 0) >= 0 {
		return "", "", ErrInvalidProof
	}
	if command == CommandBind && port == 0 {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsUnspecified() {
			return "", "", ErrInvalidProof
		}
	}
	return network, net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func capabilityForCommand(command byte) string {
	switch command {
	case CommandConnect:
		return CapabilityConnect
	case CommandBind:
		return CapabilityBind
	case CommandUDPAssociate:
		return CapabilityUDPAssociate
	default:
		return ""
	}
}

func wildcardEndpoint(address string) bool {
	host, portText, err := net.SplitHostPort(address)
	if err != nil || portText != "0" {
		return false
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ip.IsUnspecified()
}

func zeroPortAddress(address string) bool { return wildcardEndpoint(address) }
