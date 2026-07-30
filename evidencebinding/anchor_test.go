package evidencebinding

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestImmuDBAnchorUsesVerifiedSafeSetAndSafeGet(t *testing.T) {
	var mu sync.Mutex
	stored := map[string]string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case immuSafeSetPath:
			if r.Header.Get("Idempotency-Key") == "" {
				t.Error("missing idempotency key")
			}
			var request struct {
				KV struct{ Key, Value string } `json:"kv"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			stored[request.KV.Key] = request.KV.Value
			mu.Unlock()
			_, _ = w.Write([]byte(`{"tx":7}`))
		case immuSafeGetPath:
			var request struct {
				Key string `json:"key"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			value := stored[request.Key]
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]string{"value": value}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	provider := ImmuDBAnchor{BaseURL: server.URL, Token: "token", Client: server.Client()}
	head := anchorTestHead()
	receipt, err := provider.Anchor(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Provider != ImmuDBProviderName || !receipt.Committed || receipt.ExternalID == "" {
		t.Fatalf("receipt=%+v", receipt)
	}
	if err := provider.Verify(context.Background(), head, receipt); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestImmuDBAnchorRejectsSubstitutedVerifiedValue(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == immuSafeSetPath {
			_, _ = w.Write([]byte(`{"tx":1}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"item": map[string]string{"value": base64.StdEncoding.EncodeToString([]byte("different statement"))}})
	}))
	defer server.Close()
	provider := ImmuDBAnchor{BaseURL: server.URL, Client: server.Client()}
	if _, err := provider.Anchor(context.Background(), anchorTestHead()); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("err=%v", err)
	}
}

func TestFabricAnchorRequiresCommittedExactStatementEcho(t *testing.T) {
	var anchored AnchorStatement
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request fabricAnchorRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		if request.Channel != "audit" || request.Chaincode != "evidence" || request.IdempotencyKey == "" {
			t.Errorf("request=%+v", request)
		}
		switch r.URL.Path {
		case fabricSubmitPath:
			anchored = request.Statement
			_ = json.NewEncoder(w).Encode(fabricAnchorResponse{TransactionID: "tx-42", BlockNumber: 9, Successful: true, Statement: anchored})
		case fabricEvaluatePath:
			_ = json.NewEncoder(w).Encode(fabricAnchorResponse{TransactionID: "tx-42", BlockNumber: 9, Successful: true, Statement: anchored})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	provider := FabricAnchor{BaseURL: server.URL, Token: "token", Channel: "audit", Chaincode: "evidence", Contract: "notary", Client: server.Client()}
	head := anchorTestHead()
	receipt, err := provider.Anchor(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ExternalID != "tx-42" || receipt.BlockNumber != 9 {
		t.Fatalf("receipt=%+v", receipt)
	}
	if err := provider.Verify(context.Background(), head, receipt); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestFabricAnchorRejectsFailedCommitAndChangedEcho(t *testing.T) {
	head := anchorTestHead()
	t.Run("failed commit", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request fabricAnchorRequest
			_ = json.NewDecoder(r.Body).Decode(&request)
			_ = json.NewEncoder(w).Encode(fabricAnchorResponse{TransactionID: "tx-failed", BlockNumber: 4, Successful: false, Statement: request.Statement})
		}))
		defer server.Close()
		provider := FabricAnchor{BaseURL: server.URL, Channel: "audit", Chaincode: "evidence", Client: server.Client()}
		if _, err := provider.Anchor(context.Background(), head); !errors.Is(err, ErrAnchorNotCommitted) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("changed echo", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var request fabricAnchorRequest
			_ = json.NewDecoder(r.Body).Decode(&request)
			request.Statement.StatementSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			_ = json.NewEncoder(w).Encode(fabricAnchorResponse{TransactionID: "tx-evil", BlockNumber: 5, Successful: true, Statement: request.Statement})
		}))
		defer server.Close()
		provider := FabricAnchor{BaseURL: server.URL, Channel: "audit", Chaincode: "evidence", Client: server.Client()}
		if _, err := provider.Anchor(context.Background(), head); !errors.Is(err, ErrAnchorMismatch) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestAnchorReceiptCannotBeReplayedAcrossProviderOrHead(t *testing.T) {
	head := anchorTestHead()
	statement, _ := NewAnchorStatement(head)
	receipt := AnchorReceipt{Version: AnchorVersion, Provider: ImmuDBProviderName, Statement: statement, ExternalID: "key", ProofSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Committed: true}
	if err := receipt.ValidateFor(FabricProviderName, head); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("provider replay err=%v", err)
	}
	other := head
	other.Sequence++
	if err := receipt.ValidateFor(ImmuDBProviderName, other); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("head replay err=%v", err)
	}
}

func anchorTestHead() Head {
	return Head{StreamID: "audit/production", Sequence: 3, StatementSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
}
