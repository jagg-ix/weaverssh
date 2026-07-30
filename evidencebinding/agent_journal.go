package evidencebinding

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	AgentEventVersion   = "weaverssh.agent-evidence-event.v1"
	AgentJournalVersion = "weaverssh.agent-evidence-journal.v1"
)

// AgentEvent is the canonical, non-secret description of one agent lifecycle or
// connection event. Details must not contain credentials, X11 cookies, proof
// payloads, private keys, or unredacted application data.
type AgentEvent struct {
	Version        string            `json:"version"`
	ID             string            `json:"id"`
	Kind           string            `json:"kind"`
	Subject        string            `json:"subject"`
	ObservedAtUnix int64             `json:"observed_at_unix"`
	Details        map[string]string `json:"details,omitempty"`
}

func NewAgentEvent(kind, subject string, details map[string]string, observedAt time.Time) (AgentEvent, error) {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	id, err := randomNonce(18)
	if err != nil {
		return AgentEvent{}, err
	}
	event := AgentEvent{
		Version:        AgentEventVersion,
		ID:             id,
		Kind:           strings.TrimSpace(kind),
		Subject:        strings.TrimSpace(subject),
		ObservedAtUnix: observedAt.Unix(),
		Details:        cloneStringMap(details),
	}
	return event, event.Validate()
}

func (e AgentEvent) Validate() error {
	if e.Version != AgentEventVersion || strings.TrimSpace(e.ID) == "" || strings.TrimSpace(e.Kind) == "" || strings.TrimSpace(e.Subject) == "" || e.ObservedAtUnix <= 0 {
		return fmt.Errorf("%w: invalid agent event", ErrInvalidEvidence)
	}
	for key := range e.Details {
		if strings.TrimSpace(key) == "" {
			return fmt.Errorf("%w: empty agent event detail key", ErrInvalidEvidence)
		}
	}
	return nil
}

func (e AgentEvent) CanonicalBytes() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// AgentEvidenceRecord retains the event, inclusion proof, signed append-only
// checkpoint, resulting head, and provider receipt needed for later verification.
type AgentEvidenceRecord struct {
	Version   string          `json:"version"`
	Event     AgentEvent      `json:"event"`
	Leaf      Leaf            `json:"leaf"`
	Proof     MerkleProof     `json:"proof"`
	Statement SignedStatement `json:"statement"`
	Head      Head            `json:"head"`
	Receipt   AnchorReceipt   `json:"receipt"`
}

type AgentJournalConfig struct {
	Directory     string
	StreamID      string
	LedgerPath    string
	SignerKeyPath string
}

type AgentJournalStatus struct {
	Version         string        `json:"version"`
	StreamID        string        `json:"stream_id"`
	Records         int           `json:"records"`
	SignerKeyID     string        `json:"signer_key_id"`
	Head            *Head         `json:"head,omitempty"`
	Receipt         *AnchorReceipt `json:"receipt,omitempty"`
	LastEventKind   string        `json:"last_event_kind,omitempty"`
	LastObservedAt  int64         `json:"last_observed_at_unix,omitempty"`
}

type AgentJournalExport struct {
	Version string                `json:"version"`
	Status  AgentJournalStatus    `json:"status"`
	Records []AgentEvidenceRecord `json:"records"`
}

// AgentEvidenceJournal writes newline-delimited, signed checkpoints to an
// owner-only file and anchors each resulting head through an AnchorProvider.
// Reopening the journal verifies the entire chain and every retained receipt.
type AgentEvidenceJournal struct {
	mu         sync.Mutex
	config     AgentJournalConfig
	provider   AnchorProvider
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	trust      TrustPolicy
	file       *os.File
	records    []AgentEvidenceRecord
	ids        map[string]struct{}
	closed     bool
}

func OpenAgentEvidenceJournal(ctx context.Context, config AgentJournalConfig, provider AnchorProvider) (*AgentEvidenceJournal, error) {
	if provider == nil || strings.TrimSpace(provider.Name()) == "" {
		return nil, fmt.Errorf("%w: agent journal anchor provider is required", ErrInvalidAnchor)
	}
	config.Directory = strings.TrimSpace(config.Directory)
	if config.Directory == "" {
		return nil, fmt.Errorf("%w: agent journal directory is required", ErrInvalidEvidence)
	}
	absolute, err := filepath.Abs(filepath.Clean(config.Directory))
	if err != nil {
		return nil, err
	}
	if err := ensureOwnerDirectory(absolute); err != nil {
		return nil, err
	}
	config.Directory = absolute
	if strings.TrimSpace(config.StreamID) == "" {
		config.StreamID = "agent/" + strings.TrimSpace(provider.Name())
	}
	if strings.TrimSpace(config.LedgerPath) == "" {
		config.LedgerPath = filepath.Join(absolute, "agent-evidence.jsonl")
	}
	if strings.TrimSpace(config.SignerKeyPath) == "" {
		config.SignerKeyPath = filepath.Join(absolute, "agent-evidence-ed25519.key")
	}
	if err := rejectSymlink(config.LedgerPath); err != nil {
		return nil, err
	}
	if err := rejectSymlink(config.SignerKeyPath); err != nil {
		return nil, err
	}

	privateKey, err := loadOrCreateJournalKey(config.SignerKeyPath)
	if err != nil {
		return nil, err
	}
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	keyID := KeyID(publicKey)
	trust, err := NewTrustPolicy(map[string]ed25519.PublicKey{keyID: publicKey})
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(config.LedgerPath, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(config.LedgerPath, 0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	journal := &AgentEvidenceJournal{
		config: config, provider: provider, privateKey: privateKey, publicKey: publicKey,
		keyID: keyID, trust: trust, file: file, ids: make(map[string]struct{}),
	}
	if err := journal.loadAndVerify(ctx); err != nil {
		_ = file.Close()
		return nil, err
	}
	return journal, nil
}

func (j *AgentEvidenceJournal) Append(ctx context.Context, event AgentEvent) (AgentEvidenceRecord, error) {
	if j == nil {
		return AgentEvidenceRecord{}, ErrInvalidEvidence
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := event.Validate(); err != nil {
		return AgentEvidenceRecord{}, err
	}
	event.Details = cloneStringMap(event.Details)

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.file == nil {
		return AgentEvidenceRecord{}, fmt.Errorf("%w: agent journal is closed", ErrInvalidEvidence)
	}
	if _, duplicate := j.ids[event.ID]; duplicate {
		return AgentEvidenceRecord{}, fmt.Errorf("%w: %s", ErrDuplicateEvidence, event.ID)
	}
	payload, err := event.CanonicalBytes()
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	leaf, err := NewLeaf(event.ID, event.Subject, event.Kind, payload, time.Unix(event.ObservedAtUnix, 0).UTC())
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	proof, err := BuildMerkleProof([]Leaf{leaf}, 0)
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	sequence := uint64(len(j.records) + 1)
	previous := ""
	if len(j.records) > 0 {
		previous = j.records[len(j.records)-1].Head.StatementSHA256
	}
	nonce, err := randomNonce(24)
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	statement, err := NewStatement(j.config.StreamID, sequence, previous, []Leaf{leaf}, j.keyID, nonce, time.Unix(event.ObservedAtUnix, 0).UTC())
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	signed, err := SignStatement(statement, j.privateKey)
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	digest, err := statement.SHA256()
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	head := Head{StreamID: j.config.StreamID, Sequence: sequence, StatementSHA256: digest}
	receipt, err := j.provider.Anchor(ctx, head)
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	record := AgentEvidenceRecord{
		Version: AgentJournalVersion, Event: event, Leaf: leaf, Proof: proof,
		Statement: signed, Head: head, Receipt: receipt,
	}
	if err := j.verifyRecord(ctx, record); err != nil {
		return AgentEvidenceRecord{}, err
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	encoded = append(encoded, '\n')
	if _, err := j.file.Write(encoded); err != nil {
		return AgentEvidenceRecord{}, err
	}
	if err := j.file.Sync(); err != nil {
		return AgentEvidenceRecord{}, err
	}
	j.records = append(j.records, record)
	j.ids[event.ID] = struct{}{}
	return cloneAgentEvidenceRecord(record), nil
}

func (j *AgentEvidenceJournal) Record(ctx context.Context, kind, subject string, details map[string]string) (AgentEvidenceRecord, error) {
	event, err := NewAgentEvent(kind, subject, details, time.Now().UTC())
	if err != nil {
		return AgentEvidenceRecord{}, err
	}
	return j.Append(ctx, event)
}

func (j *AgentEvidenceJournal) Status() AgentJournalStatus {
	if j == nil {
		return AgentJournalStatus{Version: AgentJournalVersion}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	status := AgentJournalStatus{Version: AgentJournalVersion, StreamID: j.config.StreamID, Records: len(j.records), SignerKeyID: j.keyID}
	if len(j.records) > 0 {
		last := j.records[len(j.records)-1]
		head := last.Head
		receipt := last.Receipt
		status.Head = &head
		status.Receipt = &receipt
		status.LastEventKind = last.Event.Kind
		status.LastObservedAt = last.Event.ObservedAtUnix
	}
	return status
}

func (j *AgentEvidenceJournal) Verify(ctx context.Context) (VerificationReport, error) {
	if j == nil {
		return VerificationReport{}, ErrInvalidEvidence
	}
	if ctx == nil {
		ctx = context.Background()
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.verifyRecords(ctx, j.records)
}

func (j *AgentEvidenceJournal) Export() AgentJournalExport {
	if j == nil {
		return AgentJournalExport{Version: AgentJournalVersion}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
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

func (j *AgentEvidenceJournal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	if j.file == nil {
		return nil
	}
	err := j.file.Close()
	j.file = nil
	return err
}

func (j *AgentEvidenceJournal) loadAndVerify(ctx context.Context) error {
	if _, err := j.file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	scanner := bufio.NewScanner(j.file)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	line := 0
	for scanner.Scan() {
		line++
		data := bytes.TrimSpace(scanner.Bytes())
		if len(data) == 0 {
			return fmt.Errorf("%w: empty journal line %d", ErrInvalidEvidence, line)
		}
		var record AgentEvidenceRecord
		if err := decodeJournalJSON(data, &record); err != nil {
			return fmt.Errorf("decode agent journal line %d: %w", line, err)
		}
		if _, duplicate := j.ids[record.Event.ID]; duplicate {
			return fmt.Errorf("%w: %s", ErrDuplicateEvidence, record.Event.ID)
		}
		if err := j.verifyRecord(ctx, record); err != nil {
			return fmt.Errorf("verify agent journal line %d: %w", line, err)
		}
		j.records = append(j.records, record)
		j.ids[record.Event.ID] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if len(j.records) > 0 {
		if _, err := j.verifyRecords(ctx, j.records); err != nil {
			return err
		}
	}
	_, err := j.file.Seek(0, io.SeekEnd)
	return err
}

func (j *AgentEvidenceJournal) verifyRecord(ctx context.Context, record AgentEvidenceRecord) error {
	if record.Version != AgentJournalVersion || record.Event.Version != AgentEventVersion {
		return ErrInvalidEvidence
	}
	payload, err := record.Event.CanonicalBytes()
	if err != nil {
		return err
	}
	if err := record.Leaf.Validate(); err != nil || record.Leaf.ID != record.Event.ID || record.Leaf.Kind != record.Event.Kind || record.Leaf.Subject != record.Event.Subject || !record.Leaf.VerifyPayload(payload) {
		return ErrInvalidEvidence
	}
	if record.Statement.Statement.StreamID != j.config.StreamID || record.Statement.Statement.SignerKeyID != j.keyID || record.Statement.Statement.LeafCount != 1 || record.Statement.Statement.MerkleRootSHA256 == "" {
		return ErrInvalidEvidence
	}
	if err := VerifyMerkleProof(record.Leaf, record.Statement.Statement.MerkleRootSHA256, record.Proof); err != nil {
		return err
	}
	if err := j.trust.Verify(record.Statement); err != nil {
		return err
	}
	digest, err := record.Statement.Statement.SHA256()
	if err != nil {
		return err
	}
	expectedHead := Head{StreamID: j.config.StreamID, Sequence: record.Statement.Statement.Sequence, StatementSHA256: digest}
	if record.Head != expectedHead {
		return ErrHeadMismatch
	}
	return j.provider.Verify(ctx, record.Head, record.Receipt)
}

func (j *AgentEvidenceJournal) verifyRecords(ctx context.Context, records []AgentEvidenceRecord) (VerificationReport, error) {
	if len(records) == 0 {
		return VerificationReport{}, fmt.Errorf("%w: empty agent journal", ErrInvalidEvidence)
	}
	statements := make([]SignedStatement, len(records))
	for index, record := range records {
		if err := j.verifyRecord(ctx, record); err != nil {
			return VerificationReport{}, err
		}
		statements[index] = record.Statement
	}
	last := records[len(records)-1].Head
	return VerifyLedger(statements, j.trust, VerifyOptions{ExpectedStreamID: j.config.StreamID, WitnessedHead: &last})
}

func loadOrCreateJournalKey(path string) (ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(data)))
		if decodeErr != nil || len(decoded) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("%w: invalid agent journal private key", ErrInvalidEvidence)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		return ed25519.PrivateKey(append([]byte(nil), decoded...)), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, privateKey, _, err := GenerateEd25519Signer()
	if err != nil {
		return nil, err
	}
	encoded := base64.RawURLEncoding.EncodeToString(privateKey) + "\n"
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(file, encoded); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return privateKey, nil
}

func ensureOwnerDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: journal root must be a directory, not a symbolic link", ErrInvalidEvidence)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: symbolic-link journal files are rejected", ErrInvalidEvidence)
	}
	return nil
}

func decodeJournalJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidEvidence
	}
	return nil
}

func cloneStringMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func cloneAgentEvidenceRecord(record AgentEvidenceRecord) AgentEvidenceRecord {
	encoded, err := json.Marshal(record)
	if err != nil {
		return record
	}
	var cloned AgentEvidenceRecord
	if err := json.Unmarshal(encoded, &cloned); err != nil {
		return record
	}
	return cloned
}
