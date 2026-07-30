package evidencebinding

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	Version          = "weaverssh.evidence-binding.v1"
	AlgorithmEd25519 = "ed25519"
)

var (
	ErrInvalidEvidence   = errors.New("invalid evidence")
	ErrInvalidProof      = errors.New("invalid merkle proof")
	ErrInvalidSignature  = errors.New("invalid evidence signature")
	ErrUntrustedSigner   = errors.New("untrusted evidence signer")
	ErrBrokenChain       = errors.New("broken evidence statement chain")
	ErrWrongStream       = errors.New("evidence statement belongs to another stream")
	ErrHeadMismatch      = errors.New("evidence head does not match witnessed head")
	ErrEquivocation      = errors.New("conflicting signed statements for the same stream sequence")
	ErrDuplicateEvidence = errors.New("duplicate evidence identifier")
)

const (
	leafDomain      = "weaverssh:evidence:leaf:v1\x00"
	nodeDomain      = "weaverssh:evidence:node:v1\x00"
	statementDomain = "weaverssh:evidence:statement:v1\x00"
)

// Leaf binds an evidence identifier and semantic subject to the digest of the
// exact bytes observed. Payload bytes are intentionally not embedded.
type Leaf struct {
	ID             string `json:"id"`
	Subject        string `json:"subject"`
	Kind           string `json:"kind"`
	PayloadSHA256  string `json:"payload_sha256"`
	ObservedAtUnix int64  `json:"observed_at_unix"`
}

func NewLeaf(id, subject, kind string, payload []byte, observedAt time.Time) (Leaf, error) {
	if observedAt.IsZero() {
		observedAt = time.Now()
	}
	sum := sha256.Sum256(payload)
	leaf := Leaf{
		ID:             strings.TrimSpace(id),
		Subject:        strings.TrimSpace(subject),
		Kind:           strings.TrimSpace(kind),
		PayloadSHA256:  hex.EncodeToString(sum[:]),
		ObservedAtUnix: observedAt.Unix(),
	}
	return leaf, leaf.Validate()
}

func (l Leaf) Validate() error {
	if strings.TrimSpace(l.ID) == "" || strings.TrimSpace(l.Subject) == "" || strings.TrimSpace(l.Kind) == "" {
		return fmt.Errorf("%w: leaf identity, subject, and kind are required", ErrInvalidEvidence)
	}
	if !isSHA256(l.PayloadSHA256) {
		return fmt.Errorf("%w: payload digest must be lowercase SHA-256", ErrInvalidEvidence)
	}
	if l.ObservedAtUnix <= 0 {
		return fmt.Errorf("%w: observed time must be positive", ErrInvalidEvidence)
	}
	return nil
}

func (l Leaf) VerifyPayload(payload []byte) bool {
	sum := sha256.Sum256(payload)
	return strings.EqualFold(l.PayloadSHA256, hex.EncodeToString(sum[:]))
}

func (l Leaf) canonicalBytes() ([]byte, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(l)
}

func hashLeaf(l Leaf) ([32]byte, error) {
	canonical, err := l.canonicalBytes()
	if err != nil {
		return [32]byte{}, err
	}
	payload := make([]byte, 1, 1+len(leafDomain)+len(canonical))
	payload[0] = 0
	payload = append(payload, leafDomain...)
	payload = append(payload, canonical...)
	return sha256.Sum256(payload), nil
}

func hashNode(left, right [32]byte) [32]byte {
	payload := make([]byte, 1, 1+len(nodeDomain)+64)
	payload[0] = 1
	payload = append(payload, nodeDomain...)
	payload = append(payload, left[:]...)
	payload = append(payload, right[:]...)
	return sha256.Sum256(payload)
}

type ProofStep struct {
	SHA256 string `json:"sha256"`
	Left   bool   `json:"left"`
}

type MerkleProof struct {
	Index     int         `json:"index"`
	LeafCount int         `json:"leaf_count"`
	Siblings  []ProofStep `json:"siblings"`
}

func BuildMerkleRoot(leaves []Leaf) (string, error) {
	levels, err := merkleLevels(leaves)
	if err != nil {
		return "", err
	}
	root := levels[len(levels)-1][0]
	return hex.EncodeToString(root[:]), nil
}

func BuildMerkleProof(leaves []Leaf, index int) (MerkleProof, error) {
	if index < 0 || index >= len(leaves) {
		return MerkleProof{}, fmt.Errorf("%w: index %d outside %d leaves", ErrInvalidProof, index, len(leaves))
	}
	levels, err := merkleLevels(leaves)
	if err != nil {
		return MerkleProof{}, err
	}
	proof := MerkleProof{Index: index, LeafCount: len(leaves)}
	position := index
	for level := 0; level < len(levels)-1; level++ {
		nodes := levels[level]
		sibling := position ^ 1
		if sibling >= len(nodes) {
			sibling = position
		}
		proof.Siblings = append(proof.Siblings, ProofStep{
			SHA256: hex.EncodeToString(nodes[sibling][:]),
			Left:   sibling < position,
		})
		position /= 2
	}
	return proof, nil
}

func VerifyMerkleProof(leaf Leaf, rootSHA256 string, proof MerkleProof) error {
	if proof.LeafCount <= 0 || proof.Index < 0 || proof.Index >= proof.LeafCount || !isSHA256(rootSHA256) {
		return ErrInvalidProof
	}
	current, err := hashLeaf(leaf)
	if err != nil {
		return err
	}
	position := proof.Index
	width := proof.LeafCount
	for _, step := range proof.Siblings {
		siblingBytes, err := hex.DecodeString(step.SHA256)
		if err != nil || len(siblingBytes) != sha256.Size {
			return ErrInvalidProof
		}
		var sibling [32]byte
		copy(sibling[:], siblingBytes)
		expectedLeft := position%2 == 1
		if position == width-1 && width%2 == 1 {
			expectedLeft = false
		}
		if step.Left != expectedLeft {
			return ErrInvalidProof
		}
		if step.Left {
			current = hashNode(sibling, current)
		} else {
			current = hashNode(current, sibling)
		}
		position /= 2
		width = (width + 1) / 2
	}
	if position != 0 || width != 1 || !strings.EqualFold(rootSHA256, hex.EncodeToString(current[:])) {
		return ErrInvalidProof
	}
	return nil
}

func merkleLevels(leaves []Leaf) ([][][32]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("%w: at least one leaf is required", ErrInvalidEvidence)
	}
	seen := make(map[string]struct{}, len(leaves))
	first := make([][32]byte, len(leaves))
	for i, leaf := range leaves {
		if _, exists := seen[leaf.ID]; exists {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateEvidence, leaf.ID)
		}
		seen[leaf.ID] = struct{}{}
		hash, err := hashLeaf(leaf)
		if err != nil {
			return nil, err
		}
		first[i] = hash
	}
	levels := [][][32]byte{first}
	for len(levels[len(levels)-1]) > 1 {
		current := levels[len(levels)-1]
		next := make([][32]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			right := current[i]
			if i+1 < len(current) {
				right = current[i+1]
			}
			next = append(next, hashNode(current[i], right))
		}
		levels = append(levels, next)
	}
	return levels, nil
}

// Statement is the signed checkpoint for one append-only evidence stream.
type Statement struct {
	Version          string `json:"version"`
	StreamID         string `json:"stream_id"`
	Sequence         uint64 `json:"sequence"`
	PreviousSHA256   string `json:"previous_sha256,omitempty"`
	MerkleRootSHA256 string `json:"merkle_root_sha256"`
	LeafCount        int    `json:"leaf_count"`
	IssuedAtUnix     int64  `json:"issued_at_unix"`
	SignerKeyID      string `json:"signer_key_id"`
	Nonce            string `json:"nonce"`
}

func NewStatement(streamID string, sequence uint64, previousSHA256 string, leaves []Leaf, signerKeyID, nonce string, issuedAt time.Time) (Statement, error) {
	root, err := BuildMerkleRoot(leaves)
	if err != nil {
		return Statement{}, err
	}
	if issuedAt.IsZero() {
		issuedAt = time.Now()
	}
	statement := Statement{
		Version:          Version,
		StreamID:         strings.TrimSpace(streamID),
		Sequence:         sequence,
		PreviousSHA256:   strings.ToLower(strings.TrimSpace(previousSHA256)),
		MerkleRootSHA256: root,
		LeafCount:        len(leaves),
		IssuedAtUnix:     issuedAt.Unix(),
		SignerKeyID:      strings.TrimSpace(signerKeyID),
		Nonce:            strings.TrimSpace(nonce),
	}
	return statement, statement.Validate()
}

func (s Statement) Validate() error {
	if s.Version != Version || strings.TrimSpace(s.StreamID) == "" || s.Sequence == 0 || s.LeafCount <= 0 || s.IssuedAtUnix <= 0 || strings.TrimSpace(s.SignerKeyID) == "" || strings.TrimSpace(s.Nonce) == "" {
		return ErrInvalidEvidence
	}
	if !isSHA256(s.MerkleRootSHA256) {
		return ErrInvalidEvidence
	}
	if s.Sequence == 1 {
		if strings.TrimSpace(s.PreviousSHA256) != "" {
			return ErrBrokenChain
		}
	} else if !isSHA256(s.PreviousSHA256) {
		return ErrBrokenChain
	}
	return nil
}

func (s Statement) canonicalBytes() ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

func (s Statement) SHA256() (string, error) {
	canonical, err := s.canonicalBytes()
	if err != nil {
		return "", err
	}
	payload := append([]byte(statementDomain), canonical...)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

type SignedStatement struct {
	Statement Statement `json:"statement"`
	Algorithm string    `json:"algorithm"`
	PublicKey string    `json:"public_key"`
	Signature string    `json:"signature"`
}

func GenerateEd25519Signer() (ed25519.PublicKey, ed25519.PrivateKey, string, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	return publicKey, privateKey, KeyID(publicKey), nil
}

func KeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "ed25519:" + hex.EncodeToString(sum[:])
}

func SignStatement(statement Statement, privateKey ed25519.PrivateKey) (SignedStatement, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedStatement{}, ErrInvalidSignature
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if statement.SignerKeyID != KeyID(publicKey) {
		return SignedStatement{}, fmt.Errorf("%w: signer key id does not match private key", ErrInvalidEvidence)
	}
	canonical, err := statement.canonicalBytes()
	if err != nil {
		return SignedStatement{}, err
	}
	signature := ed25519.Sign(privateKey, append([]byte(statementDomain), canonical...))
	return SignedStatement{
		Statement: statement,
		Algorithm: AlgorithmEd25519,
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

type TrustPolicy struct {
	keys map[string]ed25519.PublicKey
}

func NewTrustPolicy(keys map[string]ed25519.PublicKey) (TrustPolicy, error) {
	policy := TrustPolicy{keys: make(map[string]ed25519.PublicKey, len(keys))}
	for keyID, key := range keys {
		if len(key) != ed25519.PublicKeySize || keyID != KeyID(key) {
			return TrustPolicy{}, fmt.Errorf("%w: invalid key entry %q", ErrUntrustedSigner, keyID)
		}
		policy.keys[keyID] = append(ed25519.PublicKey(nil), key...)
	}
	return policy, nil
}

func (p TrustPolicy) Verify(signed SignedStatement) error {
	if signed.Algorithm != AlgorithmEd25519 {
		return ErrInvalidSignature
	}
	trusted, ok := p.keys[signed.Statement.SignerKeyID]
	if !ok {
		return ErrUntrustedSigner
	}
	encodedPublic, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signed.PublicKey))
	if err != nil || len(encodedPublic) != ed25519.PublicKeySize || !bytes.Equal(trusted, encodedPublic) {
		return ErrUntrustedSigner
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signed.Signature))
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	canonical, err := signed.Statement.canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(trusted, append([]byte(statementDomain), canonical...), signature) {
		return ErrInvalidSignature
	}
	return nil
}

func DecodeSignedStatement(data []byte) (SignedStatement, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var signed SignedStatement
	if err := decoder.Decode(&signed); err != nil {
		return SignedStatement{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return SignedStatement{}, fmt.Errorf("%w: trailing JSON value", ErrInvalidEvidence)
		}
		return SignedStatement{}, err
	}
	return signed, nil
}

type Head struct {
	StreamID        string `json:"stream_id"`
	Sequence        uint64 `json:"sequence"`
	StatementSHA256 string `json:"statement_sha256"`
}

type VerifyOptions struct {
	ExpectedStreamID string
	WitnessedHead    *Head
}

type VerificationReport struct {
	StreamID          string
	Statements        int
	Head              Head
	Authentic         bool
	CompletenessBound bool
}

func VerifyLedger(statements []SignedStatement, trust TrustPolicy, options VerifyOptions) (VerificationReport, error) {
	if len(statements) == 0 {
		return VerificationReport{}, fmt.Errorf("%w: empty ledger", ErrInvalidEvidence)
	}
	expectedStream := strings.TrimSpace(options.ExpectedStreamID)
	if expectedStream == "" {
		expectedStream = statements[0].Statement.StreamID
	}
	var previousDigest string
	for index, signed := range statements {
		if signed.Statement.StreamID != expectedStream {
			return VerificationReport{}, ErrWrongStream
		}
		if signed.Statement.Sequence != uint64(index+1) || signed.Statement.PreviousSHA256 != previousDigest {
			return VerificationReport{}, ErrBrokenChain
		}
		if err := trust.Verify(signed); err != nil {
			return VerificationReport{}, err
		}
		digest, err := signed.Statement.SHA256()
		if err != nil {
			return VerificationReport{}, err
		}
		previousDigest = digest
	}
	head := Head{StreamID: expectedStream, Sequence: uint64(len(statements)), StatementSHA256: previousDigest}
	report := VerificationReport{StreamID: expectedStream, Statements: len(statements), Head: head, Authentic: true}
	if options.WitnessedHead != nil {
		report.CompletenessBound = true
		if *options.WitnessedHead != head {
			return VerificationReport{}, ErrHeadMismatch
		}
	}
	return report, nil
}

// Witness records statement digests by stream and sequence. It detects a signer
// presenting two independently valid histories for the same position.
type Witness struct {
	mu   sync.Mutex
	seen map[string]string
}

func NewWitness() *Witness {
	return &Witness{seen: make(map[string]string)}
}

func (w *Witness) Observe(signed SignedStatement, trust TrustPolicy) (Head, error) {
	if w == nil {
		return Head{}, ErrInvalidEvidence
	}
	if err := trust.Verify(signed); err != nil {
		return Head{}, err
	}
	digest, err := signed.Statement.SHA256()
	if err != nil {
		return Head{}, err
	}
	key := fmt.Sprintf("%s\x00%020d", signed.Statement.StreamID, signed.Statement.Sequence)
	w.mu.Lock()
	defer w.mu.Unlock()
	if prior, exists := w.seen[key]; exists && prior != digest {
		return Head{}, ErrEquivocation
	}
	w.seen[key] = digest
	return Head{StreamID: signed.Statement.StreamID, Sequence: signed.Statement.Sequence, StatementSHA256: digest}, nil
}

func SortLeaves(leaves []Leaf) []Leaf {
	out := append([]Leaf(nil), leaves...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func isSHA256(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
