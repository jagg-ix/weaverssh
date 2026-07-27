package authproof

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"time"
)

// AgentMessageSigner selects one Ed25519 identity from an SSH-compatible agent
// and signs arbitrary canonical protocol bytes. Private-key material never
// enters the weaverssh process.
type AgentMessageSigner struct {
	Provider     string
	Socket       string
	Identity     string
	IdentityFile string
	PublicKey    string
	PublicKeyFile string
	Timeout      time.Duration
}

// Sign returns the selected public key, its SHA-256 fingerprint, and an Ed25519
// signature over message.
func (s AgentMessageSigner) Sign(message []byte) (ed25519.PublicKey, string, []byte, error) {
	provider := NormalizeSignerProvider(s.Provider)
	if provider == SignerProviderKeyMaterial {
		provider = SignerProviderSSHAgent
	}
	cfg := RuntimeConfig{
		SignerProvider: provider,
		AgentSocket: strings.TrimSpace(s.Socket),
		Identity: strings.TrimSpace(s.Identity),
		IdentityFile: strings.TrimSpace(s.IdentityFile),
		PublicKey: strings.TrimSpace(s.PublicKey),
		PublicKeyFile: strings.TrimSpace(s.PublicKeyFile),
	}
	socket, err := cfg.ResolveSignerAgentSocket(provider)
	if err != nil {
		return nil, "", nil, err
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := sshAgentClient{SocketPath: socket, Timeout: timeout}
	identities, err := client.Identities()
	if err != nil {
		return nil, "", nil, err
	}
	identity, err := cfg.selectSSHAgentIdentity(identities)
	if err != nil {
		return nil, "", nil, err
	}
	signature, err := client.Sign(identity.Blob, message)
	if err != nil {
		return nil, "", nil, err
	}
	if len(identity.PublicKey) != ed25519.PublicKeySize {
		return nil, "", nil, fmt.Errorf("%w: selected agent identity is not Ed25519", ErrInvalidGrant)
	}
	return append(ed25519.PublicKey(nil), identity.PublicKey...), identity.FingerprintSHA256, signature, nil
}

// VerifyMessage verifies one raw Ed25519 signature over canonical bytes.
func VerifyMessage(publicKey ed25519.PublicKey, message, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}
