package evidencebinding

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"
)

func TestNonRepudiationBindsPayloadMerkleRootAndSigner(t *testing.T) {
	publicKey, privateKey, keyID, err := GenerateEd25519Signer()
	if err != nil {
		t.Fatal(err)
	}
	trust := mustTrust(t, map[string]ed25519.PublicKey{keyID: publicKey})
	now := time.Unix(1_800_000_000, 0)
	payload := []byte("operator approved transfer 8fbe")
	leaf, err := NewLeaf("event-1", "transfer:8fbe", "approval", payload, now)
	if err != nil {
		t.Fatal(err)
	}
	root, err := BuildMerkleRoot([]Leaf{leaf})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := BuildMerkleProof([]Leaf{leaf}, 0)
	if err != nil {
		t.Fatal(err)
	}
	statement, err := NewStatement("audit/production", 1, "", []Leaf{leaf}, keyID, "nonce-1", now)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignStatement(statement, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	report, err := VerifyLedger([]SignedStatement{signed}, trust, VerifyOptions{ExpectedStreamID: "audit/production"})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Authentic || report.CompletenessBound {
		t.Fatalf("unexpected report: %+v", report)
	}
	if !leaf.VerifyPayload(payload) {
		t.Fatal("original payload no longer matches its signed digest")
	}
	if err := VerifyMerkleProof(leaf, root, proof); err != nil {
		t.Fatalf("valid inclusion proof failed: %v", err)
	}
}

func TestNonRepudiationRejectsPayloadAndStatementTampering(t *testing.T) {
	publicKey, privateKey, keyID, _ := GenerateEd25519Signer()
	trust := mustTrust(t, map[string]ed25519.PublicKey{keyID: publicKey})
	now := time.Unix(1_800_000_100, 0)
	leaf, _ := NewLeaf("event-1", "transfer:8fbe", "approval", []byte("approved"), now)
	statement, _ := NewStatement("audit/production", 1, "", []Leaf{leaf}, keyID, "nonce-1", now)
	signed, _ := SignStatement(statement, privateKey)

	if leaf.VerifyPayload([]byte("denied")) {
		t.Fatal("different payload matched the committed digest")
	}

	mutated := signed
	mutated.Statement.MerkleRootSHA256 = repeatHex('a')
	if err := trust.Verify(mutated); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("tampered statement error=%v", err)
	}

	proof, _ := BuildMerkleProof([]Leaf{leaf}, 0)
	root, _ := BuildMerkleRoot([]Leaf{leaf})
	mutatedLeaf := leaf
	mutatedLeaf.Subject = "transfer:other"
	if err := VerifyMerkleProof(mutatedLeaf, root, proof); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("tampered leaf proof error=%v", err)
	}
}

func TestNonRepudiationRejectsKeySubstitutionAndCrossStreamReplay(t *testing.T) {
	publicKey, privateKey, keyID, _ := GenerateEd25519Signer()
	roguePublic, _, rogueKeyID, _ := GenerateEd25519Signer()
	trust := mustTrust(t, map[string]ed25519.PublicKey{keyID: publicKey})
	now := time.Unix(1_800_000_200, 0)
	leaf, _ := NewLeaf("event-1", "job:42", "execution", []byte("completed"), now)
	statement, _ := NewStatement("audit/production", 1, "", []Leaf{leaf}, keyID, "nonce-1", now)
	signed, _ := SignStatement(statement, privateKey)

	substituted := signed
	substituted.Statement.SignerKeyID = rogueKeyID
	substituted.PublicKey = encodePublic(roguePublic)
	if err := trust.Verify(substituted); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("key substitution error=%v", err)
	}

	if _, err := VerifyLedger([]SignedStatement{signed}, trust, VerifyOptions{ExpectedStreamID: "audit/staging"}); !errors.Is(err, ErrWrongStream) {
		t.Fatalf("cross-stream replay error=%v", err)
	}
}

func TestNonRepudiationRejectsRemovalReorderingReplayAndWitnessedTruncation(t *testing.T) {
	publicKey, privateKey, keyID, _ := GenerateEd25519Signer()
	trust := mustTrust(t, map[string]ed25519.PublicKey{keyID: publicKey})
	chain := buildChain(t, privateKey, keyID, 3)
	full, err := VerifyLedger(chain, trust, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	removed := []SignedStatement{chain[0], chain[2]}
	if _, err := VerifyLedger(removed, trust, VerifyOptions{}); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("removal error=%v", err)
	}
	reordered := []SignedStatement{chain[1], chain[0], chain[2]}
	if _, err := VerifyLedger(reordered, trust, VerifyOptions{}); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("reorder error=%v", err)
	}
	replayed := []SignedStatement{chain[0], chain[1], chain[1], chain[2]}
	if _, err := VerifyLedger(replayed, trust, VerifyOptions{}); !errors.Is(err, ErrBrokenChain) {
		t.Fatalf("replay error=%v", err)
	}

	truncated := chain[:2]
	structural, err := VerifyLedger(truncated, trust, VerifyOptions{})
	if err != nil {
		t.Fatalf("authentic prefix should remain structurally valid: %v", err)
	}
	if structural.CompletenessBound {
		t.Fatal("unwitnessed prefix incorrectly claimed completeness")
	}
	if _, err := VerifyLedger(truncated, trust, VerifyOptions{WitnessedHead: &full.Head}); !errors.Is(err, ErrHeadMismatch) {
		t.Fatalf("witnessed truncation error=%v", err)
	}
}

func TestNonRepudiationWitnessDetectsSignerEquivocation(t *testing.T) {
	publicKey, privateKey, keyID, _ := GenerateEd25519Signer()
	trust := mustTrust(t, map[string]ed25519.PublicKey{keyID: publicKey})
	now := time.Unix(1_800_000_300, 0)
	leftLeaf, _ := NewLeaf("left", "job:42", "result", []byte("success"), now)
	rightLeaf, _ := NewLeaf("right", "job:42", "result", []byte("failure"), now)
	leftStatement, _ := NewStatement("audit/production", 1, "", []Leaf{leftLeaf}, keyID, "nonce-left", now)
	rightStatement, _ := NewStatement("audit/production", 1, "", []Leaf{rightLeaf}, keyID, "nonce-right", now)
	left, _ := SignStatement(leftStatement, privateKey)
	right, _ := SignStatement(rightStatement, privateKey)

	witness := NewWitness()
	if _, err := witness.Observe(left, trust); err != nil {
		t.Fatal(err)
	}
	if _, err := witness.Observe(right, trust); !errors.Is(err, ErrEquivocation) {
		t.Fatalf("equivocation error=%v", err)
	}
	if _, err := witness.Observe(left, trust); err != nil {
		t.Fatalf("idempotent observation failed: %v", err)
	}
}

func TestNonRepudiationDetachedReceiptSurvivesLocalRecordDenial(t *testing.T) {
	publicKey, privateKey, keyID, _ := GenerateEd25519Signer()
	trust := mustTrust(t, map[string]ed25519.PublicKey{keyID: publicKey})
	chain := buildChain(t, privateKey, keyID, 1)
	receiptBytes, err := json.Marshal(chain[0])
	if err != nil {
		t.Fatal(err)
	}

	// The producer may later delete or deny its local database. The independently
	// retained signed receipt still authenticates the exact checkpoint.
	receipt, err := DecodeSignedStatement(receiptBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.Verify(receipt); err != nil {
		t.Fatalf("detached receipt did not verify: %v", err)
	}

	injected := append(append([]byte(nil), receiptBytes...), []byte(` {"denial":true}`)...)
	if _, err := DecodeSignedStatement(injected); err == nil {
		t.Fatal("decoder accepted a second trailing JSON value")
	}
}

func buildChain(t *testing.T, privateKey ed25519.PrivateKey, keyID string, count int) []SignedStatement {
	t.Helper()
	chain := make([]SignedStatement, 0, count)
	previous := ""
	for index := 1; index <= count; index++ {
		now := time.Unix(1_800_001_000+int64(index), 0)
		leaf, err := NewLeaf(
			"event-"+strconv.Itoa(index),
			"job:42",
			"result",
			[]byte{byte(index)},
			now,
		)
		if err != nil {
			t.Fatal(err)
		}
		statement, err := NewStatement("audit/production", uint64(index), previous, []Leaf{leaf}, keyID, "nonce-"+strconv.Itoa(index), now)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := SignStatement(statement, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		previous, err = statement.SHA256()
		if err != nil {
			t.Fatal(err)
		}
		chain = append(chain, signed)
	}
	return chain
}

func mustTrust(t *testing.T, keys map[string]ed25519.PublicKey) TrustPolicy {
	t.Helper()
	policy, err := NewTrustPolicy(keys)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func encodePublic(key ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(key)
}

func repeatHex(r byte) string {
	out := make([]byte, 64)
	for i := range out {
		out[i] = r
	}
	return string(out)
}
