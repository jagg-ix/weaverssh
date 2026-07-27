package authproof

import (
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDecodePublicKeyAcceptsOpenSSHEd25519PublicKey(t *testing.T) {
	v := loadVector(t)
	_, publicKey := vectorKeys(t, v)
	line, err := MarshalOpenSSHEd25519PublicKey(publicKey, "origin@example")
	if err != nil {
		t.Fatalf("marshal openssh public key: %v", err)
	}
	decoded, err := DecodePublicKey(line)
	if err != nil {
		t.Fatalf("decode openssh public key: %v", err)
	}
	if !decoded.Equal(publicKey) {
		t.Fatal("decoded OpenSSH public key mismatch")
	}
}

func TestRuntimeConfigSignsWithSSHAgentProvider(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-domain ssh-agent sockets are not portable on windows")
	}
	v := loadVector(t)
	privateKey, publicKey := vectorKeys(t, v)
	socket := startFakeSSHAgent(t, privateKey, "origin-agent-key")
	publicKeyLine, err := MarshalOpenSSHEd25519PublicKey(publicKey, "origin-agent-key")
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	now := time.Unix(1781234567, 0)
	cookieHash := HashX11Cookie("runtime-cookie")
	chainHash := ChainBindingSHA256("origin", "node-a")
	signer := RuntimeConfig{
		Mode:                 ProofModeRequired,
		SignerProvider:       SignerProviderSSHAgent,
		AgentSocket:          socket,
		Identity:             "origin-agent-key",
		IssuerPeerID:         "origin-alise-workstation",
		SubjectPeerID:        "agent-linode-a",
		Audience:             AudienceAgent,
		X11CookieSHA256:      cookieHash,
		ChainSHA256:          chainHash,
		TTL:                  time.Minute,
		RequiredCapabilities: DefaultRelayCapabilities(),
	}
	proof, err := signer.Sign(now)
	if err != nil {
		t.Fatalf("sign with ssh-agent: %v", err)
	}
	verifier := RuntimeConfig{
		Mode:                 ProofModeRequired,
		SubjectPeerID:        signer.SubjectPeerID,
		Audience:             signer.Audience,
		PublicKey:            publicKeyLine,
		X11CookieSHA256:      cookieHash,
		ChainSHA256:          chainHash,
		TTL:                  time.Minute,
		RequiredCapabilities: DefaultRelayCapabilities(),
		ReplayCache:          NewNonceCache(),
	}
	if _, err := verifier.Verify(proof, now.Add(time.Second)); err != nil {
		t.Fatalf("verify ssh-agent proof: %v", err)
	}
}

func TestRuntimeConfigSignsWithGPGAgentSSHSocketProvider(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-domain ssh-agent sockets are not portable on windows")
	}
	v := loadVector(t)
	privateKey, publicKey := vectorKeys(t, v)
	socket := startFakeSSHAgent(t, privateKey, "gpg-agent-ssh-key")
	t.Setenv("WEAVERSSH_GPG_AGENT_SSH_AUTH_SOCK", socket)
	publicKeyLine, err := MarshalOpenSSHEd25519PublicKey(publicKey, "gpg-agent-ssh-key")
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	now := time.Unix(1781234567, 0)
	signer := RuntimeConfig{
		Mode:                 ProofModeRequired,
		SignerProvider:       SignerProviderGPGAgent,
		Identity:             publicKeyLine,
		IssuerPeerID:         "origin-alise-workstation",
		SubjectPeerID:        "agent-linode-a",
		Audience:             AudienceAgent,
		X11CookieSHA256:      HashX11Cookie("runtime-cookie"),
		ChainSHA256:          ChainBindingSHA256("origin", "node-a"),
		TTL:                  time.Minute,
		RequiredCapabilities: DefaultRelayCapabilities(),
	}
	proof, err := signer.Sign(now)
	if err != nil {
		t.Fatalf("sign with gpg-agent ssh socket: %v", err)
	}
	verifier := signer
	verifier.SignerProvider = ""
	verifier.Identity = ""
	verifier.PublicKey = publicKeyLine
	verifier.ReplayCache = NewNonceCache()
	if _, err := verifier.Verify(proof, now.Add(time.Second)); err != nil {
		t.Fatalf("verify gpg-agent proof: %v", err)
	}
}

func TestSSHAgentProviderRequiresIdentityWhenMultipleKeys(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-domain ssh-agent sockets are not portable on windows")
	}
	_, key1, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key1: %v", err)
	}
	_, key2, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key2: %v", err)
	}
	socket := startFakeSSHAgentWithKeys(t, []fakeAgentKey{{privateKey: key1, comment: "one"}, {privateKey: key2, comment: "two"}})
	cfg := RuntimeConfig{SignerProvider: SignerProviderSSHAgent, AgentSocket: socket}
	ids, err := (sshAgentClient{SocketPath: socket}).Identities()
	if err != nil {
		t.Fatalf("identities: %v", err)
	}
	_, err = cfg.selectSSHAgentIdentity(ids)
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected identity selection failure, got %v", err)
	}
	cfg.Identity = "two"
	selected, err := cfg.selectSSHAgentIdentity(ids)
	if err != nil {
		t.Fatalf("select identity by comment: %v", err)
	}
	if selected.Comment != "two" {
		t.Fatalf("selected %q, want two", selected.Comment)
	}
}

type fakeAgentKey struct {
	privateKey ed25519.PrivateKey
	comment    string
}

func startFakeSSHAgent(t *testing.T, privateKey ed25519.PrivateKey, comment string) string {
	t.Helper()
	return startFakeSSHAgentWithKeys(t, []fakeAgentKey{{privateKey: privateKey, comment: comment}})
}

func startFakeSSHAgentWithKeys(t *testing.T, keys []fakeAgentKey) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "wvagt-")
	if err != nil {
		t.Fatalf("make fake agent dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "a.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen fake agent: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		_ = os.Remove(socket)
	})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleFakeSSHAgentConn(t, conn, keys)
		}
	}()
	return socket
}

func handleFakeSSHAgentConn(t *testing.T, conn net.Conn, keys []fakeAgentKey) {
	defer conn.Close()
	for {
		payload, err := readAgentMessage(conn)
		if err != nil {
			return
		}
		if len(payload) == 0 {
			return
		}
		switch payload[0] {
		case sshAgentCRequestIdentities:
			var out []byte
			out = append(out, sshAgentCIdentitiesAnswer)
			out = appendUint32(out, uint32(len(keys)))
			for _, key := range keys {
				publicKey := key.privateKey.Public().(ed25519.PublicKey)
				out = appendSSHString(out, marshalSSHEd25519PublicKeyBlob(publicKey))
				out = appendSSHString(out, []byte(key.comment))
			}
			_ = writeAgentMessage(conn, out)
		case sshAgentCSignRequest:
			reader := sshWireReader{data: payload[1:]}
			blob, err := reader.string()
			if err != nil {
				_ = writeAgentMessage(conn, []byte{sshAgentFailure})
				continue
			}
			data, err := reader.string()
			if err != nil {
				_ = writeAgentMessage(conn, []byte{sshAgentFailure})
				continue
			}
			_, _ = reader.uint32()
			var signingKey ed25519.PrivateKey
			for _, key := range keys {
				publicKey := key.privateKey.Public().(ed25519.PublicKey)
				if string(blob) == string(marshalSSHEd25519PublicKeyBlob(publicKey)) {
					signingKey = key.privateKey
					break
				}
			}
			if signingKey == nil {
				_ = writeAgentMessage(conn, []byte{sshAgentFailure})
				continue
			}
			sig := ed25519.Sign(signingKey, data)
			var sigBlob []byte
			sigBlob = appendSSHString(sigBlob, []byte("ssh-ed25519"))
			sigBlob = appendSSHString(sigBlob, sig)
			out := append([]byte{sshAgentCSignResponse}, appendSSHString(nil, sigBlob)...)
			_ = writeAgentMessage(conn, out)
		default:
			t.Logf("fake agent unexpected message type %d", payload[0])
			_ = writeAgentMessage(conn, []byte{sshAgentFailure})
		}
	}
}
