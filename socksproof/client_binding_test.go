package socksproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestClientRejectsUnexpectedChallengeBinding(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name             string
		expectedServerID string
		expectedPolicy   string
		expectedNode     string
		want             string
	}{
		{name: "server", expectedServerID: "proxy-b", expectedPolicy: policyDigest, expectedNode: "compute-node", want: "server ID"},
		{name: "policy", expectedServerID: "proxy-a", expectedPolicy: strings.Repeat("b", 64), expectedNode: "compute-node", want: "policy digest"},
		{name: "node", expectedServerID: "proxy-a", expectedPolicy: policyDigest, expectedNode: "other-node", want: "selected node"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			challenge, err := NewChallenge("proxy-a", policyDigest, "binding-a", "compute-node", 30*time.Second, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(server, greeting); err != nil {
					done <- err
					return
				}
				if _, err := server.Write([]byte{0x05, MethodPrivate}); err != nil {
					done <- err
					return
				}
				done <- WriteFrame(server, challenge)
			}()
			_, err = HandshakeClient(client, "api.internal:443", ClientConfig{
				Principal:            "client-a",
				Capabilities:         []string{CapabilityConnect},
				Signer:               Ed25519Signer(privateKey),
				ProofTTL:             20 * time.Second,
				ExpectedServerID:     test.expectedServerID,
				ExpectedPolicySHA256: test.expectedPolicy,
				ExpectedNode:         test.expectedNode,
			})
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v", err)
			}
			if serverErr := <-done; serverErr != nil && !errors.Is(serverErr, net.ErrClosed) {
				t.Fatal(serverErr)
			}
		})
	}
}
