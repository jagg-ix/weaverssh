package evidencebinding

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	FabricProviderName = "fabric"
	fabricSubmitPath   = "/v1/fabric/submit"
	fabricEvaluatePath = "/v1/fabric/evaluate"
)

type FabricAnchor struct {
	BaseURL        string
	Token          string
	Channel        string
	Chaincode      string
	Contract       string
	SubmitFunction string
	QueryFunction  string
	Client         *http.Client
}

func (p FabricAnchor) Name() string { return FabricProviderName }

type fabricAnchorRequest struct {
	Channel        string          `json:"channel"`
	Chaincode      string          `json:"chaincode"`
	Contract       string          `json:"contract,omitempty"`
	Function       string          `json:"function"`
	IdempotencyKey string          `json:"idempotency_key"`
	Statement      AnchorStatement `json:"statement"`
}

type fabricAnchorResponse struct {
	TransactionID string          `json:"transaction_id"`
	BlockNumber   uint64          `json:"block_number"`
	Successful    bool            `json:"successful"`
	Statement     AnchorStatement `json:"statement"`
}

func (p FabricAnchor) Anchor(ctx context.Context, head Head) (AnchorReceipt, error) {
	statement, err := NewAnchorStatement(head)
	if err != nil {
		return AnchorReceipt{}, err
	}
	idempotencyKey, err := anchorIdempotencyKey(statement)
	if err != nil {
		return AnchorReceipt{}, err
	}
	request, err := p.request(statement, p.submitFunction(), idempotencyKey)
	if err != nil {
		return AnchorReceipt{}, err
	}
	raw, response, err := p.call(ctx, fabricSubmitPath, request)
	if err != nil {
		return AnchorReceipt{}, err
	}
	if !response.Successful {
		return AnchorReceipt{}, ErrAnchorNotCommitted
	}
	if response.Statement != statement {
		return AnchorReceipt{}, ErrAnchorMismatch
	}
	if strings.TrimSpace(response.TransactionID) == "" || response.BlockNumber == 0 {
		return AnchorReceipt{}, fmt.Errorf("%w: fabric response lacks committed transaction metadata", ErrInvalidAnchor)
	}
	return AnchorReceipt{
		Version: AnchorVersion, Provider: p.Name(), Statement: statement,
		ExternalID: response.TransactionID, ProofSHA256: anchorProofSHA256(raw),
		Committed: true, BlockNumber: response.BlockNumber,
	}, nil
}

func (p FabricAnchor) Verify(ctx context.Context, head Head, receipt AnchorReceipt) error {
	if err := receipt.ValidateFor(p.Name(), head); err != nil {
		return err
	}
	if receipt.BlockNumber == 0 {
		return fmt.Errorf("%w: fabric receipt lacks block number", ErrInvalidAnchor)
	}
	idempotencyKey, err := anchorIdempotencyKey(receipt.Statement)
	if err != nil {
		return err
	}
	request, err := p.request(receipt.Statement, p.queryFunction(), idempotencyKey)
	if err != nil {
		return err
	}
	_, response, err := p.call(ctx, fabricEvaluatePath, request)
	if err != nil {
		return err
	}
	if !response.Successful {
		return ErrAnchorRejected
	}
	if response.Statement != receipt.Statement {
		return ErrAnchorMismatch
	}
	if response.TransactionID != "" && response.TransactionID != receipt.ExternalID {
		return ErrAnchorMismatch
	}
	if response.BlockNumber != 0 && response.BlockNumber != receipt.BlockNumber {
		return ErrAnchorMismatch
	}
	return nil
}

func (p FabricAnchor) request(statement AnchorStatement, function, idempotencyKey string) (fabricAnchorRequest, error) {
	channel := strings.TrimSpace(p.Channel)
	chaincode := strings.TrimSpace(p.Chaincode)
	function = strings.TrimSpace(function)
	if strings.TrimSpace(p.BaseURL) == "" || channel == "" || chaincode == "" || function == "" {
		return fabricAnchorRequest{}, fmt.Errorf("%w: fabric base URL, channel, chaincode, and function are required", ErrInvalidAnchor)
	}
	return fabricAnchorRequest{
		Channel: channel, Chaincode: chaincode, Contract: strings.TrimSpace(p.Contract),
		Function: function, IdempotencyKey: idempotencyKey, Statement: statement,
	}, nil
}

func (p FabricAnchor) submitFunction() string {
	if value := strings.TrimSpace(p.SubmitFunction); value != "" {
		return value
	}
	return "AnchorEvidence"
}

func (p FabricAnchor) queryFunction() string {
	if value := strings.TrimSpace(p.QueryFunction); value != "" {
		return value
	}
	return "ReadEvidenceAnchor"
}

func (p FabricAnchor) call(ctx context.Context, path string, body fabricAnchorRequest) ([]byte, fabricAnchorResponse, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fabricAnchorResponse{}, err
	}
	endpoint := strings.TrimRight(strings.TrimSpace(p.BaseURL), "/") + path
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, fabricAnchorResponse{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	if token := strings.TrimSpace(p.Token); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, fabricAnchorResponse{}, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return nil, fabricAnchorResponse{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fabricAnchorResponse{}, fmt.Errorf("%w: fabric bridge status %d", ErrAnchorRejected, response.StatusCode)
	}
	var decoded fabricAnchorResponse
	if err := decodeAnchorJSONStrict(raw, &decoded); err != nil {
		return nil, fabricAnchorResponse{}, err
	}
	return raw, decoded, nil
}
