package evidencebinding

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	AgentJournalSnapshotVersion = "weaverssh.agent-evidence-snapshot.v1"
	agentSnapshotDomain         = "weaverssh:agent-evidence-snapshot:v1\x00"
)

type AgentJournalSnapshot struct {
	Version        string             `json:"version"`
	CreatedAtUnix  int64              `json:"created_at_unix"`
	SignerKeyID    string             `json:"signer_key_id"`
	PublicKey      string             `json:"public_key"`
	PayloadSHA256  string             `json:"payload_sha256"`
	Signature      string             `json:"signature"`
	Export         AgentJournalExport `json:"export"`
	RemoteDelivery *AgentRemoteQueueExport `json:"remote_delivery,omitempty"`
}

type agentSnapshotPayload struct {
	Version        string                  `json:"version"`
	CreatedAtUnix  int64                   `json:"created_at_unix"`
	SignerKeyID    string                  `json:"signer_key_id"`
	PublicKey      string                  `json:"public_key"`
	Export         AgentJournalExport      `json:"export"`
	RemoteDelivery *AgentRemoteQueueExport `json:"remote_delivery,omitempty"`
}

// Snapshot signs an exact portable copy of the retained journal. Remote queue
// state may be attached by the agent wrapper through SnapshotWithRemote.
func (j *AgentEvidenceJournal) Snapshot() (AgentJournalSnapshot, error) {
	return j.SnapshotWithRemote(nil)
}

func (j *AgentEvidenceJournal) SnapshotWithRemote(remote *AgentRemoteQueueExport) (AgentJournalSnapshot, error) {
	if j == nil {
		return AgentJournalSnapshot{}, ErrInvalidEvidence
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.file == nil {
		return AgentJournalSnapshot{}, fmt.Errorf("%w: agent journal is closed", ErrInvalidEvidence)
	}
	exported := j.exportLocked()
	created := time.Now().UTC().Unix()
	publicKey := base64.RawURLEncoding.EncodeToString(j.publicKey)
	payload := agentSnapshotPayload{
		Version: AgentJournalSnapshotVersion, CreatedAtUnix: created,
		SignerKeyID: j.keyID, PublicKey: publicKey, Export: exported,
	}
	if remote != nil {
		cloned := cloneRemoteExport(*remote)
		payload.RemoteDelivery = &cloned
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return AgentJournalSnapshot{}, err
	}
	digest := sha256.Sum256(canonical)
	signature := ed25519.Sign(j.privateKey, append([]byte(agentSnapshotDomain), canonical...))
	return AgentJournalSnapshot{
		Version: payload.Version, CreatedAtUnix: created, SignerKeyID: j.keyID,
		PublicKey: publicKey, PayloadSHA256: hex.EncodeToString(digest[:]),
		Signature: base64.RawURLEncoding.EncodeToString(signature), Export: exported,
		RemoteDelivery: payload.RemoteDelivery,
	}, nil
}

// VerifyAgentJournalSnapshot verifies the bundle signature, every event payload,
// Merkle inclusion proof, checkpoint signature, chain edge, head, and provider
// receipt binding. It does not contact remote provider backends.
func VerifyAgentJournalSnapshot(snapshot AgentJournalSnapshot) (VerificationReport, error) {
	if snapshot.Version != AgentJournalSnapshotVersion || snapshot.CreatedAtUnix <= 0 || strings.TrimSpace(snapshot.SignerKeyID) == "" {
		return VerificationReport{}, ErrInvalidEvidence
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(snapshot.PublicKey))
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return VerificationReport{}, ErrInvalidSignature
	}
	if KeyID(ed25519.PublicKey(publicKey)) != snapshot.SignerKeyID {
		return VerificationReport{}, ErrUntrustedSigner
	}
	payload := agentSnapshotPayload{
		Version: snapshot.Version, CreatedAtUnix: snapshot.CreatedAtUnix,
		SignerKeyID: snapshot.SignerKeyID, PublicKey: snapshot.PublicKey,
		Export: snapshot.Export, RemoteDelivery: snapshot.RemoteDelivery,
	}
	canonical, err := json.Marshal(payload)
	if err != nil {
		return VerificationReport{}, err
	}
	digest := sha256.Sum256(canonical)
	if snapshot.PayloadSHA256 != hex.EncodeToString(digest[:]) {
		return VerificationReport{}, ErrInvalidEvidence
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(snapshot.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(publicKey), append([]byte(agentSnapshotDomain), canonical...), signature) {
		return VerificationReport{}, ErrInvalidSignature
	}
	return verifySnapshotExport(snapshot.Export, ed25519.PublicKey(publicKey), snapshot.SignerKeyID)
}

func DecodeAgentJournalSnapshot(data []byte) (AgentJournalSnapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snapshot AgentJournalSnapshot
	if err := decoder.Decode(&snapshot); err != nil {
		return AgentJournalSnapshot{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return AgentJournalSnapshot{}, ErrInvalidEvidence
	}
	return snapshot, nil
}

func verifySnapshotExport(exported AgentJournalExport, publicKey ed25519.PublicKey, keyID string) (VerificationReport, error) {
	if exported.Version != AgentJournalVersion || exported.Status.Version != AgentJournalVersion || len(exported.Records) == 0 {
		return VerificationReport{}, ErrInvalidEvidence
	}
	if exported.Status.Records != len(exported.Records) || exported.Status.SignerKeyID != keyID {
		return VerificationReport{}, ErrInvalidEvidence
	}
	trust, err := NewTrustPolicy(map[string]ed25519.PublicKey{keyID: publicKey})
	if err != nil {
		return VerificationReport{}, err
	}
	statements := make([]SignedStatement, len(exported.Records))
	for index, record := range exported.Records {
		if record.Version != AgentJournalVersion || record.Event.Version != AgentEventVersion {
			return VerificationReport{}, ErrInvalidEvidence
		}
		payload, err := record.Event.CanonicalBytes()
		if err != nil {
			return VerificationReport{}, err
		}
		if err := record.Leaf.Validate(); err != nil || record.Leaf.ID != record.Event.ID || record.Leaf.Kind != record.Event.Kind || record.Leaf.Subject != record.Event.Subject || !record.Leaf.VerifyPayload(payload) {
			return VerificationReport{}, ErrInvalidEvidence
		}
		if record.Statement.Statement.SignerKeyID != keyID || record.Statement.Statement.StreamID != exported.Status.StreamID {
			return VerificationReport{}, ErrInvalidEvidence
		}
		if err := VerifyMerkleProof(record.Leaf, record.Statement.Statement.MerkleRootSHA256, record.Proof); err != nil {
			return VerificationReport{}, err
		}
		if err := trust.Verify(record.Statement); err != nil {
			return VerificationReport{}, err
		}
		digest, err := record.Statement.Statement.SHA256()
		if err != nil {
			return VerificationReport{}, err
		}
		expectedHead := Head{StreamID: exported.Status.StreamID, Sequence: record.Statement.Statement.Sequence, StatementSHA256: digest}
		if record.Head != expectedHead || record.Receipt.ValidateFor(record.Receipt.Provider, record.Head) != nil {
			return VerificationReport{}, ErrHeadMismatch
		}
		statements[index] = record.Statement
	}
	last := exported.Records[len(exported.Records)-1]
	if exported.Status.Head == nil || *exported.Status.Head != last.Head || exported.Status.Receipt == nil || *exported.Status.Receipt != last.Receipt {
		return VerificationReport{}, ErrHeadMismatch
	}
	return VerifyLedger(statements, trust, VerifyOptions{ExpectedStreamID: exported.Status.StreamID, WitnessedHead: exported.Status.Head})
}

func (j *AgentEvidenceJournal) exportLocked() AgentJournalExport {
	records := make([]AgentEvidenceRecord, len(j.records))
	for index, record := range j.records {
		records[index] = cloneAgentEvidenceRecord(record)
	}
	status := AgentJournalStatus{Version: AgentJournalVersion, StreamID: j.config.StreamID, Records: len(records), SignerKeyID: j.keyID}
	if len(records) > 0 {
		last := records[len(records)-1]
		head := last.Head
		receipt := last.Receipt
		status.Head = &head
		status.Receipt = &receipt
		status.LastEventKind = last.Event.Kind
		status.LastObservedAt = last.Event.ObservedAtUnix
	}
	return AgentJournalExport{Version: AgentJournalVersion, Status: status, Records: records}
}

func cloneRemoteExport(exported AgentRemoteQueueExport) AgentRemoteQueueExport {
	payload, _ := json.Marshal(exported)
	var cloned AgentRemoteQueueExport
	_ = json.Unmarshal(payload, &cloned)
	return cloned
}
