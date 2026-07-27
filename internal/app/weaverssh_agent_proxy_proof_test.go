package app

import (
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"weaverssh/authproof"
)

func TestVerifyWebSocketProofAcceptsFirstControlFrame(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cookieHash := authproof.HashX11Cookie("cookie")
	chainHash := authproof.DefaultChainSHA256()
	verifyConfig := AgentConfig{
		AuthTimeout: time.Second,
		Proof: authproof.RuntimeConfig{
			Mode:                 authproof.ProofModeRequired,
			SubjectPeerID:        "agent-under-test",
			Audience:             authproof.AudienceAgent,
			PublicKey:            authproof.EncodePublicKey(publicKey),
			X11CookieSHA256:      cookieHash,
			ChainSHA256:          chainHash,
			TTL:                  time.Minute,
			RequiredCapabilities: authproof.DefaultRelayCapabilities(),
			ReplayCache:          authproof.NewNonceCache(),
		},
	}

	errCh := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			errCh <- err
			return
		}
		defer ws.Close()
		_, err = verifyWebSocketProof(ws, verifyConfig)
		errCh <- err
	}))
	defer server.Close()

	url := "ws" + server.URL[len("http"):]
	client, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer client.Close()

	proof, err := authproof.SignGrant(authproof.Grant{
		Version:         authproof.Version,
		Algorithm:       authproof.Algorithm,
		IssuerPeerID:    "origin-under-test",
		SubjectPeerID:   "agent-under-test",
		Audience:        authproof.AudienceAgent,
		SessionID:       "session-under-test",
		Capabilities:    authproof.DefaultRelayCapabilities(),
		X11CookieSHA256: cookieHash,
		ChainSHA256:     chainHash,
		Nonce:           "nonce-under-test",
		IssuedAtUnix:    time.Now().Unix(),
		ExpiresAtUnix:   time.Now().Add(time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	payload, err := authproof.MarshalControlFrame(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	if err := client.WriteMessage(websocket.TextMessage, payload); err != nil {
		t.Fatalf("write proof: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("verify proof: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proof verification")
	}
}

func TestVerifyWebSocketProofRejectsNonProofFirstFrame(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verifyConfig := AgentConfig{
		AuthTimeout: time.Second,
		Proof: authproof.RuntimeConfig{
			Mode:                 authproof.ProofModeRequired,
			SubjectPeerID:        "agent-under-test",
			Audience:             authproof.AudienceAgent,
			PublicKey:            authproof.EncodePublicKey(publicKey),
			X11CookieSHA256:      authproof.HashX11Cookie("cookie"),
			ChainSHA256:          authproof.DefaultChainSHA256(),
			TTL:                  time.Minute,
			RequiredCapabilities: authproof.DefaultRelayCapabilities(),
			ReplayCache:          authproof.NewNonceCache(),
		},
	}

	errCh := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			errCh <- err
			return
		}
		defer ws.Close()
		_, err = verifyWebSocketProof(ws, verifyConfig)
		errCh <- err
	}))
	defer server.Close()

	url := "ws" + server.URL[len("http"):]
	client, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer client.Close()
	if err := client.WriteMessage(websocket.BinaryMessage, []byte("x11 bytes, not proof")); err != nil {
		t.Fatalf("write non-proof: %v", err)
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected proof verification failure")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proof verification")
	}
}

func TestAuthorizeWebSocketSessionAppliesSecurityLevels(t *testing.T) {
	base := AgentConfig{Proof: authproof.RuntimeConfig{SecurityLevel: authproof.SecurityLevelCompat}}
	if err := authorizeWebSocketSession(base, websocketAuthorityContext{}); err != nil {
		t.Fatalf("compat should allow legacy session: %v", err)
	}

	x11Cookie := AgentConfig{Proof: authproof.RuntimeConfig{SecurityLevel: authproof.SecurityLevelX11Cookie}}
	if err := authorizeWebSocketSession(x11Cookie, websocketAuthorityContext{X11Authenticated: true}); err == nil {
		t.Fatal("x11_cookie should reject without same UID evidence")
	}
	if err := authorizeWebSocketSession(x11Cookie, websocketAuthorityContext{SameUID: true}); err == nil {
		t.Fatal("x11_cookie should reject same UID without X11 cookie setup")
	}
	if err := authorizeWebSocketSession(x11Cookie, websocketAuthorityContext{SameUID: true, X11Authenticated: true}); err != nil {
		t.Fatalf("x11_cookie should accept same UID plus X11 cookie evidence: %v", err)
	}

	agentProof := AgentConfig{Proof: authproof.RuntimeConfig{SecurityLevel: authproof.SecurityLevelAgentProof}}
	if err := authorizeWebSocketSession(agentProof, websocketAuthorityContext{X11Authenticated: true}); err == nil {
		t.Fatal("agent_proof should reject X11 cookie without verified key proof")
	}
	if err := authorizeWebSocketSession(agentProof, websocketAuthorityContext{AgentKeyProofVerified: true}); err == nil {
		t.Fatal("agent_proof should reject key proof without X11 cookie setup")
	}
	if err := authorizeWebSocketSession(agentProof, websocketAuthorityContext{X11Authenticated: true, AgentKeyProofVerified: true}); err != nil {
		t.Fatalf("agent_proof should accept X11 cookie plus verified key proof: %v", err)
	}

	strict := AgentConfig{Proof: authproof.RuntimeConfig{SecurityLevel: authproof.SecurityLevelStrict}}
	if err := authorizeWebSocketSession(strict, websocketAuthorityContext{X11Authenticated: true, AgentKeyProofVerified: true}); err == nil {
		t.Fatal("strict should reject without same UID evidence")
	}
	if err := authorizeWebSocketSession(strict, websocketAuthorityContext{SameUID: true, X11Authenticated: true, AgentKeyProofVerified: true}); err != nil {
		t.Fatalf("strict should accept same UID, X11 cookie, and verified key proof: %v", err)
	}
}

func TestVerifyWebSocketProofBindsSecurityLevelForAgentProof(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cookieHash := authproof.HashX11Cookie("cookie")
	chainHash := authproof.DefaultChainSHA256()
	verifyConfig := AgentConfig{
		AuthTimeout: time.Second,
		Proof: authproof.RuntimeConfig{
			Mode:                 authproof.ProofModeOff,
			SecurityLevel:        authproof.SecurityLevelAgentProof,
			SubjectPeerID:        "agent-under-test",
			Audience:             authproof.AudienceAgent,
			PublicKey:            authproof.EncodePublicKey(publicKey),
			X11CookieSHA256:      cookieHash,
			ChainSHA256:          chainHash,
			TTL:                  time.Minute,
			RequiredCapabilities: authproof.DefaultRelayCapabilities(),
			ReplayCache:          authproof.NewNonceCache(),
		},
	}

	errCh := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			errCh <- err
			return
		}
		defer ws.Close()
		grant, err := verifyWebSocketProof(ws, verifyConfig)
		if err == nil && grant.SecurityLevel != authproof.SecurityLevelAgentProof {
			err = errors.New("security level was not bound in verified grant")
		}
		errCh <- err
	}))
	defer server.Close()

	url := "ws" + server.URL[len("http"):]
	client, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer client.Close()

	proof, err := authproof.SignGrant(authproof.Grant{
		Version:         authproof.Version,
		Algorithm:       authproof.Algorithm,
		IssuerPeerID:    "origin-under-test",
		SubjectPeerID:   "agent-under-test",
		Audience:        authproof.AudienceAgent,
		SessionID:       "session-under-test",
		Capabilities:    authproof.DefaultRelayCapabilities(),
		SecurityLevel:   authproof.SecurityLevelAgentProof,
		X11CookieSHA256: cookieHash,
		ChainSHA256:     chainHash,
		Nonce:           "nonce-agent-proof-under-test",
		IssuedAtUnix:    time.Now().Unix(),
		ExpiresAtUnix:   time.Now().Add(time.Minute).Unix(),
	}, privateKey)
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	payload, err := authproof.MarshalControlFrame(proof)
	if err != nil {
		t.Fatalf("marshal proof: %v", err)
	}
	if err := client.WriteMessage(websocket.TextMessage, payload); err != nil {
		t.Fatalf("write proof: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("verify proof: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proof verification")
	}
}
