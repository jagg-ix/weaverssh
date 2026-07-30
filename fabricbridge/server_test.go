package fabricbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"weaverssh/evidencebinding"
)

func TestSubmitWaitsForCommitAndReadsExactRecord(t *testing.T) {
	statement := evidencebinding.AnchorStatement{Version: evidencebinding.AnchorVersion, StreamID: "audit", Sequence: 4, StatementSHA256: strings.Repeat("a", 64)}
	runner := &scriptedRunner{statement: statement}
	server := Server{Config: Config{
		Token: "secret", PeerBinary: "peer-test", Orderer: "orderer.example:7050", OrdererCA: "/tls/orderer.pem",
		PeerAddresses: []string{"peer0.org1:7051"}, PeerTLSRoots: []string{"/tls/peer.pem"}, QueryFunction: "ReadEvidenceAnchor",
	}, Runner: runner}
	requestBody, _ := json.Marshal(anchorRequest{
		Channel: "audit-channel", Chaincode: "evidence", Contract: "EvidenceContract", Function: "AnchorEvidence",
		IdempotencyKey: "idem-1", Statement: statement,
	})
	request := httptest.NewRequest(http.MethodPost, SubmitPath, bytes.NewReader(requestBody))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var decoded anchorResponse
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Successful || decoded.TransactionID != "tx-123" || decoded.BlockNumber != 8 || decoded.Statement != statement {
		t.Fatalf("response=%+v", decoded)
	}
	if len(runner.calls) != 3 {
		t.Fatalf("calls=%d", len(runner.calls))
	}
	invoke := strings.Join(runner.calls[0], " ")
	if !strings.Contains(invoke, "chaincode invoke") || !strings.Contains(invoke, "--waitForEvent") || !strings.Contains(invoke, "EvidenceContract:AnchorEvidence") {
		t.Fatalf("invoke args=%s", invoke)
	}
	query := strings.Join(runner.calls[1], " ")
	if !strings.Contains(query, "EvidenceContract:ReadEvidenceAnchor") {
		t.Fatalf("query args=%s", query)
	}
}

func TestBridgeRejectsUnauthorizedAndMismatchedRecord(t *testing.T) {
	statement := evidencebinding.AnchorStatement{Version: evidencebinding.AnchorVersion, StreamID: "audit", Sequence: 1, StatementSHA256: strings.Repeat("b", 64)}
	server := Server{Config: Config{Token: "secret"}, Runner: &scriptedRunner{statement: statement, mismatch: true}}
	body, _ := json.Marshal(anchorRequest{Channel: "c", Chaincode: "cc", Function: "AnchorEvidence", IdempotencyKey: "id", Statement: statement})
	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodPost, SubmitPath, bytes.NewReader(body)))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", unauthorized.Code)
	}
	request := httptest.NewRequest(http.MethodPost, SubmitPath, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer secret")
	mismatch := httptest.NewRecorder()
	server.Handler().ServeHTTP(mismatch, request)
	if mismatch.Code != http.StatusConflict {
		t.Fatalf("mismatch status=%d body=%s", mismatch.Code, mismatch.Body.String())
	}
}

type scriptedRunner struct {
	statement evidencebinding.AnchorStatement
	mismatch  bool
	calls     [][]string
}

func (r *scriptedRunner) Run(_ context.Context, _ []string, name string, args ...string) ([]byte, []byte, error) {
	call := append([]string{name}, args...)
	r.calls = append(r.calls, call)
	joined := strings.Join(args, " ")
	switch {
	case strings.Contains(joined, "chaincode invoke"):
		return []byte("invoke successful"), nil, nil
	case strings.Contains(joined, "chaincode query"):
		statement := r.statement
		if r.mismatch {
			statement.StatementSHA256 = strings.Repeat("c", 64)
		}
		data, _ := json.Marshal(chaincodeRecord{IdempotencyKey: "idem-1", Statement: statement, TransactionID: "tx-123"})
		if strings.Contains(joined, `"id"`) {
			data, _ = json.Marshal(chaincodeRecord{IdempotencyKey: "id", Statement: statement, TransactionID: "tx-123"})
		}
		return data, nil, nil
	case strings.Contains(joined, "channel getinfo"):
		return []byte(`Blockchain info: {"height":9,"currentBlockHash":"x"}`), nil, nil
	default:
		return nil, []byte("unexpected command"), context.Canceled
	}
}
