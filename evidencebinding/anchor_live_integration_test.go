//go:build integration

package evidencebinding

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestLiveImmuDBAnchor(t *testing.T) {
	baseURL := strings.TrimSpace(os.Getenv("WEAVERSSH_IMMUGW_URL"))
	token := strings.TrimSpace(os.Getenv("WEAVERSSH_IMMUGW_TOKEN"))
	if baseURL == "" || token == "" {
		t.Skip("WEAVERSSH_IMMUGW_URL and WEAVERSSH_IMMUGW_TOKEN are required")
	}
	head := liveHead("immudb")
	provider := ImmuDBAnchor{BaseURL: baseURL, Token: token, Client: &http.Client{Timeout: 30 * time.Second}}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	receipt, err := provider.Anchor(ctx, head)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Verify(ctx, head, receipt); err != nil {
		t.Fatal(err)
	}
}

func TestLiveFabricAnchor(t *testing.T) {
	baseURL := strings.TrimSpace(os.Getenv("WEAVERSSH_FABRIC_BRIDGE_URL"))
	channel := strings.TrimSpace(os.Getenv("WEAVERSSH_FABRIC_CHANNEL"))
	chaincode := strings.TrimSpace(os.Getenv("WEAVERSSH_FABRIC_CHAINCODE"))
	if baseURL == "" || channel == "" || chaincode == "" {
		t.Skip("Fabric bridge URL, channel, and chaincode are required")
	}
	head := liveHead("fabric")
	provider := FabricAnchor{
		BaseURL: baseURL, Token: os.Getenv("WEAVERSSH_FABRIC_BRIDGE_TOKEN"), Channel: channel,
		Chaincode: chaincode, Contract: os.Getenv("WEAVERSSH_FABRIC_CONTRACT"),
		Client: &http.Client{Timeout: 90 * time.Second},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	receipt, err := provider.Anchor(ctx, head)
	if err != nil {
		t.Fatal(err)
	}
	if err := provider.Verify(ctx, head, receipt); err != nil {
		t.Fatal(err)
	}
}

func liveHead(label string) Head {
	seed := SHA256Hex([]byte(label + time.Now().UTC().Format(time.RFC3339Nano)))
	return Head{StreamID: "live/" + label, Sequence: 1, StatementSHA256: seed}
}
