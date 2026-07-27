package authproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	SignerProviderKeyMaterial = "key"
	SignerProviderSSHAgent    = "ssh-agent"
	SignerProviderGPGAgent    = "gpg-agent"
)

const (
	sshAgentCRequestIdentities = 11
	sshAgentCSignRequest       = 13
	sshAgentCSignResponse      = 14
	sshAgentCIdentitiesAnswer  = 12
	sshAgentFailure            = 5
)

type SSHAgentIdentity struct {
	Blob              []byte
	Type              string
	PublicKey         ed25519.PublicKey
	Comment           string
	FingerprintSHA256 string
}

type sshAgentClient struct {
	SocketPath string
	Timeout    time.Duration
}

func NormalizeSignerProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(provider, "_", "-"))) {
	case "", "key", "key-material", "inline", "file", "private-key", "ed25519":
		return SignerProviderKeyMaterial
	case "ssh", "ssh-agent", "sshagent", "openssh-agent", "pageant":
		return SignerProviderSSHAgent
	case "gpg", "gpg-agent", "gpgagent", "gnupg":
		return SignerProviderGPGAgent
	default:
		return strings.ToLower(strings.TrimSpace(provider))
	}
}

func KnownSignerProvider(provider string) bool {
	switch NormalizeSignerProvider(provider) {
	case SignerProviderKeyMaterial, SignerProviderSSHAgent, SignerProviderGPGAgent:
		return true
	default:
		return false
	}
}

func (c RuntimeConfig) normalizedSignerProvider() string {
	cfg := c.Normalized()
	if cfg.SignerProvider != "" {
		return NormalizeSignerProvider(cfg.SignerProvider)
	}
	if cfg.AgentSocket != "" {
		return SignerProviderSSHAgent
	}
	return SignerProviderKeyMaterial
}

func (c RuntimeConfig) ValidateSignerProvider() error {
	provider := c.normalizedSignerProvider()
	if !KnownSignerProvider(provider) {
		return fmt.Errorf("%w: unsupported signer provider %q", ErrInvalidGrant, c.SignerProvider)
	}
	switch provider {
	case SignerProviderKeyMaterial:
		_, err := c.LoadPrivateKey()
		return err
	case SignerProviderSSHAgent, SignerProviderGPGAgent:
		_, err := c.ResolveSignerAgentSocket(provider)
		return err
	default:
		return fmt.Errorf("%w: unsupported signer provider %q", ErrInvalidGrant, provider)
	}
}

func (c RuntimeConfig) ResolveSignerAgentSocket(provider string) (string, error) {
	cfg := c.Normalized()
	if cfg.AgentSocket != "" {
		return cfg.AgentSocket, nil
	}
	switch NormalizeSignerProvider(provider) {
	case SignerProviderSSHAgent:
		if sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK")); sock != "" {
			return sock, nil
		}
		return "", fmt.Errorf("%w: SSH_AUTH_SOCK is not set", ErrInvalidGrant)
	case SignerProviderGPGAgent:
		for _, name := range []string{"WEAVERSSH_GPG_AGENT_SSH_AUTH_SOCK", "GPG_AGENT_SSH_AUTH_SOCK"} {
			if sock := strings.TrimSpace(os.Getenv(name)); sock != "" {
				return sock, nil
			}
		}
		if sock, err := gpgAgentSSHSockFromGPGConf(); err == nil && sock != "" {
			return sock, nil
		}
		if sock := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK")); sock != "" {
			return sock, nil
		}
		return "", fmt.Errorf("%w: gpg-agent SSH socket not found; set --proof-agent-socket or WEAVERSSH_GPG_AGENT_SSH_AUTH_SOCK", ErrInvalidGrant)
	default:
		return "", fmt.Errorf("%w: unsupported signer provider %q", ErrInvalidGrant, provider)
	}
}

func gpgAgentSSHSockFromGPGConf() (string, error) {
	path, err := exec.LookPath("gpgconf")
	if err != nil {
		return "", err
	}
	out, err := exec.Command(path, "--list-dirs", "agent-ssh-socket").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func (c RuntimeConfig) SignWithAgent(now time.Time, provider string) (SignedGrant, error) {
	cfg := c.Normalized()
	if err := cfg.ValidateSigner(); err != nil {
		return SignedGrant{}, err
	}
	socketPath, err := cfg.ResolveSignerAgentSocket(provider)
	if err != nil {
		return SignedGrant{}, err
	}
	grant, err := cfg.BuildGrant(now, "")
	if err != nil {
		return SignedGrant{}, err
	}
	canonical, err := CanonicalBytes(grant)
	if err != nil {
		return SignedGrant{}, err
	}
	client := sshAgentClient{SocketPath: socketPath, Timeout: 10 * time.Second}
	identities, err := client.Identities()
	if err != nil {
		return SignedGrant{}, err
	}
	identity, err := cfg.selectSSHAgentIdentity(identities)
	if err != nil {
		return SignedGrant{}, err
	}
	sig, err := client.Sign(identity.Blob, canonical)
	if err != nil {
		return SignedGrant{}, err
	}
	return SignedGrant{Grant: grant.Normalized(), Signature: base64.RawURLEncoding.EncodeToString(sig)}, nil
}

func (c RuntimeConfig) selectSSHAgentIdentity(identities []SSHAgentIdentity) (SSHAgentIdentity, error) {
	if len(identities) == 0 {
		return SSHAgentIdentity{}, fmt.Errorf("%w: signer agent has no Ed25519 identities", ErrInvalidGrant)
	}
	selectors, publicKeys := c.agentIdentitySelectors()
	for _, identity := range identities {
		for _, publicKey := range publicKeys {
			if bytes.Equal(identity.PublicKey, publicKey) {
				return identity, nil
			}
		}
		for _, selector := range selectors {
			if sshAgentIdentityMatches(identity, selector) {
				return identity, nil
			}
		}
	}
	if len(selectors) == 0 && len(publicKeys) == 0 && len(identities) == 1 {
		return identities[0], nil
	}
	return SSHAgentIdentity{}, fmt.Errorf("%w: no signer agent Ed25519 identity matched; set --proof-identity or --proof-identity-file", ErrInvalidGrant)
}

func (c RuntimeConfig) agentIdentitySelectors() ([]string, []ed25519.PublicKey) {
	cfg := c.Normalized()
	var selectors []string
	var publicKeys []ed25519.PublicKey
	for _, value := range []string{cfg.Identity, readOptionalTextFile(cfg.IdentityFile), cfg.PublicKey, readOptionalTextFile(cfg.PublicKeyFile)} {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if key, err := DecodePublicKey(value); err == nil {
			publicKeys = append(publicKeys, key)
		} else {
			selectors = append(selectors, value)
		}
	}
	return selectors, publicKeys
}

func readOptionalTextFile(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func sshAgentIdentityMatches(identity SSHAgentIdentity, selector string) bool {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return false
	}
	if selector == identity.Comment || selector == identity.FingerprintSHA256 || strings.TrimPrefix(selector, "SHA256:") == strings.TrimPrefix(identity.FingerprintSHA256, "SHA256:") {
		return true
	}
	if key, err := DecodePublicKey(selector); err == nil {
		return bytes.Equal(identity.PublicKey, key)
	}
	return false
}

func (c sshAgentClient) Identities() ([]SSHAgentIdentity, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := writeAgentMessage(conn, []byte{sshAgentCRequestIdentities}); err != nil {
		return nil, err
	}
	payload, err := readAgentMessage(conn)
	if err != nil {
		return nil, err
	}
	if len(payload) == 0 || payload[0] != sshAgentCIdentitiesAnswer {
		return nil, fmt.Errorf("%w: ssh-agent identities request failed", ErrInvalidGrant)
	}
	reader := sshWireReader{data: payload[1:]}
	count, err := reader.uint32()
	if err != nil {
		return nil, err
	}
	identities := make([]SSHAgentIdentity, 0, count)
	for i := uint32(0); i < count; i++ {
		blob, err := reader.string()
		if err != nil {
			return nil, err
		}
		commentBytes, err := reader.string()
		if err != nil {
			return nil, err
		}
		keyType, publicKey, err := parseSSHEd25519PublicKeyBlob(blob)
		if err != nil {
			continue
		}
		identities = append(identities, SSHAgentIdentity{
			Blob:              append([]byte(nil), blob...),
			Type:              keyType,
			PublicKey:         publicKey,
			Comment:           string(commentBytes),
			FingerprintSHA256: sshAgentFingerprintSHA256(blob),
		})
	}
	return identities, nil
}

func (c sshAgentClient) Sign(keyBlob, data []byte) ([]byte, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var payload []byte
	payload = append(payload, sshAgentCSignRequest)
	payload = appendSSHString(payload, keyBlob)
	payload = appendSSHString(payload, data)
	payload = appendUint32(payload, 0)
	if err := writeAgentMessage(conn, payload); err != nil {
		return nil, err
	}
	response, err := readAgentMessage(conn)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 || response[0] == sshAgentFailure {
		return nil, fmt.Errorf("%w: ssh-agent refused signature", ErrInvalidSignature)
	}
	if response[0] != sshAgentCSignResponse {
		return nil, fmt.Errorf("%w: unexpected ssh-agent response %d", ErrInvalidSignature, response[0])
	}
	reader := sshWireReader{data: response[1:]}
	sigBlob, err := reader.string()
	if err != nil {
		return nil, err
	}
	format, sig, err := parseSSHSignatureBlob(sigBlob)
	if err != nil {
		return nil, err
	}
	if format != "ssh-ed25519" || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w: signer agent returned %s signature", ErrInvalidSignature, format)
	}
	return sig, nil
}

func (c sshAgentClient) dial() (net.Conn, error) {
	if strings.TrimSpace(c.SocketPath) == "" {
		return nil, fmt.Errorf("%w: signer agent socket path is empty", ErrInvalidGrant)
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	conn, err := net.DialTimeout("unix", c.SocketPath, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect signer agent %s: %w", c.SocketPath, err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func DecodeOpenSSHEd25519PublicKey(raw string) (ed25519.PublicKey, []byte, bool, error) {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) < 2 || fields[0] != "ssh-ed25519" {
		return nil, nil, false, nil
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		if blob, err = base64.RawStdEncoding.DecodeString(fields[1]); err != nil {
			return nil, nil, true, fmt.Errorf("%w: invalid OpenSSH public key blob", ErrInvalidGrant)
		}
	}
	keyType, publicKey, err := parseSSHEd25519PublicKeyBlob(blob)
	if err != nil {
		return nil, nil, true, err
	}
	if keyType != "ssh-ed25519" {
		return nil, nil, true, fmt.Errorf("%w: unsupported OpenSSH public key type %s", ErrInvalidGrant, keyType)
	}
	return publicKey, blob, true, nil
}

func MarshalOpenSSHEd25519PublicKey(publicKey ed25519.PublicKey, comment string) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("%w: Ed25519 public key must be %d bytes", ErrInvalidGrant, ed25519.PublicKeySize)
	}
	blob := marshalSSHEd25519PublicKeyBlob(publicKey)
	out := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob)
	if strings.TrimSpace(comment) != "" {
		out += " " + strings.TrimSpace(comment)
	}
	return out, nil
}

func marshalSSHEd25519PublicKeyBlob(publicKey ed25519.PublicKey) []byte {
	var blob []byte
	blob = appendSSHString(blob, []byte("ssh-ed25519"))
	blob = appendSSHString(blob, publicKey)
	return blob
}

func parseSSHEd25519PublicKeyBlob(blob []byte) (string, ed25519.PublicKey, error) {
	reader := sshWireReader{data: blob}
	keyTypeBytes, err := reader.string()
	if err != nil {
		return "", nil, err
	}
	keyType := string(keyTypeBytes)
	if keyType != "ssh-ed25519" {
		return keyType, nil, fmt.Errorf("%w: unsupported SSH public key type %s", ErrInvalidGrant, keyType)
	}
	publicKey, err := reader.string()
	if err != nil {
		return keyType, nil, err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return keyType, nil, fmt.Errorf("%w: invalid ssh-ed25519 public key length", ErrInvalidGrant)
	}
	return keyType, ed25519.PublicKey(append([]byte(nil), publicKey...)), nil
}

func parseSSHSignatureBlob(blob []byte) (string, []byte, error) {
	reader := sshWireReader{data: blob}
	formatBytes, err := reader.string()
	if err != nil {
		return "", nil, err
	}
	sig, err := reader.string()
	if err != nil {
		return "", nil, err
	}
	return string(formatBytes), append([]byte(nil), sig...), nil
}

func sshAgentFingerprintSHA256(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

type sshWireReader struct {
	data []byte
}

func (r *sshWireReader) uint32() (uint32, error) {
	if len(r.data) < 4 {
		return 0, io.ErrUnexpectedEOF
	}
	value := binary.BigEndian.Uint32(r.data[:4])
	r.data = r.data[4:]
	return value, nil
}

func (r *sshWireReader) string() ([]byte, error) {
	length, err := r.uint32()
	if err != nil {
		return nil, err
	}
	if uint64(length) > uint64(len(r.data)) {
		return nil, io.ErrUnexpectedEOF
	}
	out := r.data[:length]
	r.data = r.data[length:]
	return out, nil
}

func appendUint32(out []byte, value uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], value)
	return append(out, buf[:]...)
}

func appendSSHString(out []byte, value []byte) []byte {
	out = appendUint32(out, uint32(len(value)))
	return append(out, value...)
}

func writeAgentMessage(w io.Writer, payload []byte) error {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func readAgentMessage(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > 1<<20 {
		return nil, fmt.Errorf("%w: invalid ssh-agent response length %d", ErrInvalidGrant, length)
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(r, payload)
	return payload, err
}
