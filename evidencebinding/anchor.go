package evidencebinding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const AnchorVersion = "weaverssh.evidence-anchor.v1"

var (
	ErrInvalidAnchor      = errors.New("invalid evidence anchor")
	ErrAnchorMismatch     = errors.New("anchored statement does not match expected evidence head")
	ErrAnchorRejected     = errors.New("evidence anchor provider rejected the statement")
	ErrAnchorNotCommitted = errors.New("evidence anchor transaction was not committed")
)

type AnchorStatement struct {
	Version         string `json:"version"`
	StreamID        string `json:"stream_id"`
	Sequence        uint64 `json:"sequence"`
	StatementSHA256 string `json:"statement_sha256"`
}

func NewAnchorStatement(head Head) (AnchorStatement, error) {
	statement := AnchorStatement{
		Version: AnchorVersion, StreamID: strings.TrimSpace(head.StreamID),
		Sequence: head.Sequence, StatementSHA256: strings.ToLower(strings.TrimSpace(head.StatementSHA256)),
	}
	return statement, statement.Validate()
}

func (s AnchorStatement) Validate() error {
	if s.Version != AnchorVersion || strings.TrimSpace(s.StreamID) == "" || s.Sequence == 0 || !isSHA256(s.StatementSHA256) {
		return ErrInvalidAnchor
	}
	return nil
}

func (s AnchorStatement) CanonicalBytes() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

func (s AnchorStatement) SHA256() (string, error) {
	canonical, err := s.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("weaverssh:evidence:anchor:v1\x00"), canonical...))
	return hex.EncodeToString(sum[:]), nil
}

func (s AnchorStatement) Head() Head {
	return Head{StreamID: s.StreamID, Sequence: s.Sequence, StatementSHA256: s.StatementSHA256}
}

type AnchorReceipt struct {
	Version     string          `json:"version"`
	Provider    string          `json:"provider"`
	Statement   AnchorStatement `json:"statement"`
	ExternalID  string          `json:"external_id"`
	ProofSHA256 string          `json:"proof_sha256"`
	Committed   bool            `json:"committed"`
	BlockNumber uint64          `json:"block_number,omitempty"`
}

func (r AnchorReceipt) ValidateFor(provider string, head Head) error {
	expected, err := NewAnchorStatement(head)
	if err != nil {
		return err
	}
	if r.Version != AnchorVersion || strings.TrimSpace(r.Provider) != strings.TrimSpace(provider) || r.Statement != expected {
		return ErrAnchorMismatch
	}
	if strings.TrimSpace(r.ExternalID) == "" || !isSHA256(r.ProofSHA256) {
		return ErrInvalidAnchor
	}
	if !r.Committed {
		return ErrAnchorNotCommitted
	}
	return nil
}

type AnchorProvider interface {
	Name() string
	Anchor(context.Context, Head) (AnchorReceipt, error)
	Verify(context.Context, Head, AnchorReceipt) error
}

func anchorProofSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func anchorIdempotencyKey(statement AnchorStatement) (string, error) {
	digest, err := statement.SHA256()
	if err != nil {
		return "", err
	}
	return "weaverssh-evidence-" + digest, nil
}

func decodeAnchorJSONStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: trailing JSON value", ErrInvalidAnchor)
		}
		return err
	}
	return nil
}
