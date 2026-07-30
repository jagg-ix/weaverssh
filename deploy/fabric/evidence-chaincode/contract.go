package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

const anchorVersion = "weaverssh.evidence-anchor.v1"

type AnchorStatement struct {
	Version         string `json:"version"`
	StreamID        string `json:"stream_id"`
	Sequence        uint64 `json:"sequence"`
	StatementSHA256 string `json:"statement_sha256"`
}

type AnchorRecord struct {
	IdempotencyKey string          `json:"idempotency_key"`
	Statement      AnchorStatement `json:"statement"`
	TransactionID  string          `json:"transaction_id"`
}

type EvidenceContract struct {
	contractapi.Contract
}

func (c *EvidenceContract) AnchorEvidence(ctx contractapi.TransactionContextInterface, idempotencyKey, statementJSON string) (*AnchorRecord, error) {
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return nil, errors.New("idempotency key is required")
	}
	statement, err := decodeStatement(statementJSON)
	if err != nil {
		return nil, err
	}
	key := stateKey(idempotencyKey)
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("read existing anchor: %w", err)
	}
	if existing != nil {
		var record AnchorRecord
		if err := json.Unmarshal(existing, &record); err != nil {
			return nil, fmt.Errorf("decode existing anchor: %w", err)
		}
		if record.IdempotencyKey != idempotencyKey || record.Statement != statement {
			return nil, errors.New("idempotency key already binds a different statement")
		}
		return &record, nil
	}
	record := AnchorRecord{IdempotencyKey: idempotencyKey, Statement: statement, TransactionID: ctx.GetStub().GetTxID()}
	encoded, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if err := ctx.GetStub().PutState(key, encoded); err != nil {
		return nil, fmt.Errorf("persist evidence anchor: %w", err)
	}
	return &record, nil
}

func (c *EvidenceContract) ReadEvidenceAnchor(ctx contractapi.TransactionContextInterface, idempotencyKey string) (*AnchorRecord, error) {
	idempotencyKey = strings.TrimSpace(idempotencyKey)
	if idempotencyKey == "" {
		return nil, errors.New("idempotency key is required")
	}
	encoded, err := ctx.GetStub().GetState(stateKey(idempotencyKey))
	if err != nil {
		return nil, fmt.Errorf("read evidence anchor: %w", err)
	}
	if encoded == nil {
		return nil, errors.New("evidence anchor not found")
	}
	var record AnchorRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		return nil, fmt.Errorf("decode evidence anchor: %w", err)
	}
	if record.IdempotencyKey != idempotencyKey {
		return nil, errors.New("stored evidence anchor key mismatch")
	}
	return &record, nil
}

func decodeStatement(raw string) (AnchorStatement, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(raw)))
	decoder.DisallowUnknownFields()
	var statement AnchorStatement
	if err := decoder.Decode(&statement); err != nil {
		return AnchorStatement{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return AnchorStatement{}, errors.New("trailing statement JSON")
		}
		return AnchorStatement{}, err
	}
	statement.StreamID = strings.TrimSpace(statement.StreamID)
	statement.StatementSHA256 = strings.ToLower(strings.TrimSpace(statement.StatementSHA256))
	if statement.Version != anchorVersion || statement.StreamID == "" || statement.Sequence == 0 || !isSHA256(statement.StatementSHA256) {
		return AnchorStatement{}, errors.New("invalid anchor statement")
	}
	return statement, nil
}

func stateKey(idempotencyKey string) string {
	sum := sha256.Sum256([]byte(idempotencyKey))
	return "weaverssh:evidence-anchor:" + hex.EncodeToString(sum[:])
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
