package app

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"weaverssh/authproof"
)

func TestSOCKSHandlerSendsAuthproofAsFirstWebSocketFrame(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cookie := "cookie-from-xauth"
	proofConfig := authproof.RuntimeConfig{
		Mode:                 authproof.ProofModeRequired,
		IssuerPeerID:         "origin-under-test",
		SubjectPeerID:        "agent-under-test",
		Audience:             authproof.AudienceAgent,
		PrivateKey:           authproof.EncodePrivateKey(privateKey),
		ChainSHA256:          authproof.DefaultChainSHA256(),
		TTL:                  time.Minute,
		RequiredCapabilities: authproof.DefaultRelayCapabilities(),
	}
	handler := &SOCKSHandler{proof: proofConfig}

	errCh := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
		if err != nil {
			errCh <- err
			return
		}
		defer ws.Close()
		_, payload, err := ws.ReadMessage()
		if err != nil {
			errCh <- err
			return
		}
		proof, err := authproof.ParseControlFrame(payload)
		if err != nil {
			errCh <- err
			return
		}
		_, err = authproof.VerifySignedGrant(proof, publicKey, authproof.VerifyOptions{
			Now:                  time.Now(),
			Audience:             authproof.AudienceAgent,
			SubjectPeerID:        "agent-under-test",
			RequiredCapabilities: authproof.DefaultRelayCapabilities(),
			X11CookieSHA256:      authproof.HashX11Cookie(cookie),
			ChainSHA256:          authproof.DefaultChainSHA256(),
			MaxTTL:               time.Minute,
		})
		errCh <- err
	}))
	defer server.Close()

	url := "ws" + server.URL[len("http"):]
	client, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer client.Close()
	if err := handler.sendAgentProof(client, cookie); err != nil {
		t.Fatalf("send proof: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("verify proof: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for proof frame")
	}
}
