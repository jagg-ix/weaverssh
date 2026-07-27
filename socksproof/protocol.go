package socksproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"weaverssh/authproof"
)

const (
	ProtocolVersion   = "weaverssh.socks-proof.v1"
	MethodPrivate     = byte(0x80)
	CapabilityConnect = "socks.connect"
	maxFrameBytes     = 64 << 10
	maxChallengeTTL   = time.Minute
)

var (
	ErrInvalidProof = errors.New("socksproof: invalid proof")
	ErrExpired      = errors.New("socksproof: proof expired")
	ErrReplay       = errors.New("socksproof: replayed proof")
	ErrUnauthorized = errors.New("socksproof: unauthorized")
)

type Challenge struct {
	Protocol       string `json:"protocol"`
	ServerID       string `json:"server_id"`
	PolicySHA256   string `json:"policy_sha256"`
	SessionBinding string `json:"session_binding"`
	SelectedNode   string `json:"selected_node"`
	Nonce          string `json:"nonce"`
	IssuedAtUnix   int64  `json:"issued_at_unix"`
	ExpiresAtUnix  int64  `json:"expires_at_unix"`
}

type IdentityStatement struct {
	Protocol        string   `json:"protocol"`
	Principal       string   `json:"principal"`
	Capabilities    []string `json:"capabilities"`
	ChallengeSHA256 string   `json:"challenge_sha256"`
	Nonce           string   `json:"nonce"`
	IssuedAtUnix    int64    `json:"issued_at_unix"`
	ExpiresAtUnix   int64    `json:"expires_at_unix"`
}

type SignedIdentity struct {
	Statement IdentityStatement `json:"statement"`
	Signature string            `json:"signature"`
}

type ConnectStatement struct {
	Protocol        string `json:"protocol"`
	Principal       string `json:"principal"`
	ChallengeSHA256 string `json:"challenge_sha256"`
	IdentitySHA256  string `json:"identity_sha256"`
	Command         byte   `json:"command"`
	Network         string `json:"network"`
	Address         string `json:"address"`
	SessionBinding  string `json:"session_binding"`
	SelectedNode    string `json:"selected_node"`
	Nonce           string `json:"nonce"`
	IssuedAtUnix    int64  `json:"issued_at_unix"`
	ExpiresAtUnix   int64  `json:"expires_at_unix"`
}

type SignedConnect struct {
	Statement ConnectStatement `json:"statement"`
	Signature string           `json:"signature"`
}

type AuthResult struct {
	Protocol  string `json:"protocol"`
	OK        bool   `json:"ok"`
	Principal string `json:"principal,omitempty"`
	Error     string `json:"error,omitempty"`
}

type Signer interface {
	Sign([]byte) ([]byte, error)
}

type Ed25519Signer ed25519.PrivateKey

func (s Ed25519Signer) Sign(payload []byte) ([]byte, error) {
	key := ed25519.PrivateKey(s)
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("socksproof: invalid Ed25519 private key")
	}
	return ed25519.Sign(key, payload), nil
}

type AgentSigner struct{ Config authproof.AgentMessageSigner }

func (s AgentSigner) Sign(payload []byte) ([]byte, error) {
	_, _, signature, err := s.Config.Sign(payload)
	return signature, err
}

type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]int64
}

func NewReplayCache() *ReplayCache { return &ReplayCache{seen: map[string]int64{}} }

func (c *ReplayCache) Check(nonce string, expiry int64, now time.Time) error {
	if c == nil {
		return nil
	}
	nonce = strings.TrimSpace(nonce)
	if nonce == "" || expiry <= now.Unix() {
		return ErrInvalidProof
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, exp := range c.seen {
		if exp <= now.Unix() {
			delete(c.seen, key)
		}
	}
	if _, ok := c.seen[nonce]; ok {
		return ErrReplay
	}
	c.seen[nonce] = expiry
	return nil
}

func NewChallenge(serverID, policySHA256, binding, node string, ttl time.Duration, now time.Time) (Challenge, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	if ttl > maxChallengeTTL {
		return Challenge{}, ErrInvalidProof
	}
	nonce, err := randomNonce(32)
	if err != nil {
		return Challenge{}, err
	}
	challenge := Challenge{
		Protocol:       ProtocolVersion,
		ServerID:       strings.TrimSpace(serverID),
		PolicySHA256:   strings.ToLower(strings.TrimSpace(policySHA256)),
		SessionBinding: strings.TrimSpace(binding),
		SelectedNode:   strings.TrimSpace(node),
		Nonce:          nonce,
		IssuedAtUnix:   now.Unix(),
		ExpiresAtUnix:  now.Add(ttl).Unix(),
	}
	if err := validateChallenge(challenge, now); err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

func SignIdentity(challenge Challenge, principal string, capabilities []string, signer Signer, ttl time.Duration, now time.Time) (SignedIdentity, error) {
	if signer == nil {
		return SignedIdentity{}, errors.New("socksproof: signer required")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(challenge, now); err != nil {
		return SignedIdentity{}, err
	}
	principal = strings.TrimSpace(principal)
	capabilities = normalizeStrings(capabilities)
	if principal == "" || !contains(capabilities, CapabilityConnect) {
		return SignedIdentity{}, ErrInvalidProof
	}
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	expires := boundedExpiry(now, ttl, challenge.ExpiresAtUnix)
	if expires <= now.Unix() {
		return SignedIdentity{}, ErrExpired
	}
	nonce, err := randomNonce(24)
	if err != nil {
		return SignedIdentity{}, err
	}
	statement := IdentityStatement{
		Protocol:        ProtocolVersion,
		Principal:       principal,
		Capabilities:    capabilities,
		ChallengeSHA256: DigestChallenge(challenge),
		Nonce:           nonce,
		IssuedAtUnix:    now.Unix(),
		ExpiresAtUnix:   expires,
	}
	payload, err := canonical(statement)
	if err != nil {
		return SignedIdentity{}, err
	}
	signature, err := signer.Sign(payload)
	if err != nil {
		return SignedIdentity{}, err
	}
	if len(signature) != ed25519.SignatureSize {
		return SignedIdentity{}, authproof.ErrInvalidSignature
	}
	return SignedIdentity{Statement: statement, Signature: base64.RawURLEncoding.EncodeToString(signature)}, nil
}

func SignConnect(challenge Challenge, identity SignedIdentity, network, address string, signer Signer, ttl time.Duration, now time.Time) (SignedConnect, error) {
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
	network, address, err := NormalizeAddress(network, address)
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
		Protocol:        ProtocolVersion,
		Principal:       identity.Statement.Principal,
		ChallengeSHA256: DigestChallenge(challenge),
		IdentitySHA256:  DigestIdentity(identity),
		Command:         0x01,
		Network:         network,
		Address:         address,
		SessionBinding:  challenge.SessionBinding,
		SelectedNode:    challenge.SelectedNode,
		Nonce:           nonce,
		IssuedAtUnix:    now.Unix(),
		ExpiresAtUnix:   expires,
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

func VerifySignature(publicKey ed25519.PublicKey, statement any, signature string) error {
	payload, err := canonical(statement)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signature))
	if err != nil || len(sig) != ed25519.SignatureSize || len(publicKey) != ed25519.PublicKeySize || !ed25519.Verify(publicKey, payload, sig) {
		return authproof.ErrInvalidSignature
	}
	return nil
}

func DigestChallenge(challenge Challenge) string {
	payload, _ := canonical(challenge)
	return digest(payload)
}

func DigestIdentity(identity SignedIdentity) string {
	payload, _ := canonical(identity)
	return digest(payload)
}

func DigestConnect(proof SignedConnect) string {
	payload, _ := canonical(proof)
	return digest(payload)
}

func ValidateTime(issued, expires int64, maxTTL time.Duration, now time.Time) error {
	if now.IsZero() {
		now = time.Now()
	}
	if issued <= 0 || expires <= issued || now.Unix() < issued || now.Unix() >= expires {
		return ErrExpired
	}
	if maxTTL > 0 && time.Duration(expires-issued)*time.Second > maxTTL {
		return ErrInvalidProof
	}
	return nil
}

func WriteFrame(writer io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) == 0 || len(payload) > maxFrameBytes {
		return errors.New("socksproof: frame too large")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func ReadFrame(reader io.Reader, value any) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header)
	if length == 0 || length > maxFrameBytes {
		return errors.New("socksproof: invalid frame length")
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("socksproof: trailing JSON data")
	}
	return nil
}

func NormalizeAddress(network, address string) (string, string, error) {
	network = strings.ToLower(strings.TrimSpace(network))
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return "", "", fmt.Errorf("socksproof: unsupported network %q", network)
	}
	address = strings.TrimSpace(address)
	host, portText, err := net.SplitHostPort(address)
	if err != nil || strings.TrimSpace(host) == "" {
		return "", "", fmt.Errorf("socksproof: destination must be HOST:PORT: %q", address)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", "", fmt.Errorf("socksproof: invalid destination port %q", portText)
	}
	if strings.IndexByte(host, 0) >= 0 {
		return "", "", errors.New("socksproof: destination contains NUL")
	}
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	}
	if host == "" {
		return "", "", ErrInvalidProof
	}
	return network, net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func validateChallenge(challenge Challenge, now time.Time) error {
	if challenge.Protocol != ProtocolVersion || strings.TrimSpace(challenge.ServerID) == "" || !isSHA256Hex(challenge.PolicySHA256) || strings.TrimSpace(challenge.SessionBinding) == "" || strings.TrimSpace(challenge.SelectedNode) == "" || strings.TrimSpace(challenge.Nonce) == "" {
		return ErrInvalidProof
	}
	return ValidateTime(challenge.IssuedAtUnix, challenge.ExpiresAtUnix, maxChallengeTTL, now)
}

func isSHA256Hex(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func boundedExpiry(now time.Time, ttl time.Duration, upper int64) int64 {
	expires := now.Add(ttl).Unix()
	if upper > 0 && expires > upper {
		expires = upper
	}
	return expires
}

func randomNonce(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func canonical(value any) ([]byte, error) { return json.Marshal(value) }

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func normalizeStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func RemoteAddress(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}
