package evidencebinding

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHashChainDetectsRewrittenEntryAndWitnessedTailRewrite(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trusted, err := NewTrustedSigner("ed25519", publicKey)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewSignatureTrustPolicy([]TrustedSigner{trusted})
	if err != nil {
		t.Fatal(err)
	}

	chain := makeSignatureChain(t, privateKey, trusted.KeyID, 6)
	original, err := VerifyLedgerWithSignaturePolicy(chain, policy, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}

	for index := range chain {
		rewritten := append([]SignedStatement(nil), chain...)
		changed := rewritten[index].Statement
		changed.Nonce = fmt.Sprintf("rewritten-%d", index)
		rewritten[index], err = SignStatementWithKey(changed, "ed25519", privateKey)
		if err != nil {
			t.Fatal(err)
		}

		if index < len(chain)-1 {
			if _, err := VerifyLedgerWithSignaturePolicy(rewritten, policy, VerifyOptions{}); !errors.Is(err, ErrBrokenChain) {
				t.Fatalf("rewritten entry %d did not break successor link: %v", index, err)
			}
			continue
		}

		// Rewriting the last entry leaves no successor link to contradict it.
		// An independently retained old head is what detects the rewritten tail.
		structural, err := VerifyLedgerWithSignaturePolicy(rewritten, policy, VerifyOptions{})
		if err != nil {
			t.Fatalf("rewritten tail should remain structurally valid: %v", err)
		}
		if structural.Head == original.Head {
			t.Fatal("rewritten tail retained original head")
		}
		if _, err := VerifyLedgerWithSignaturePolicy(rewritten, policy, VerifyOptions{WitnessedHead: &original.Head}); !errors.Is(err, ErrHeadMismatch) {
			t.Fatalf("witness did not detect rewritten tail: %v", err)
		}
	}
}

func TestMerkleProofCoverageAcrossOddAndEvenTreeWidths(t *testing.T) {
	for count := 1; count <= 17; count++ {
		leaves := make([]Leaf, 0, count)
		for index := 0; index < count; index++ {
			leaf, err := NewLeaf(
				fmt.Sprintf("event-%02d", index), "transfer:42", "audit",
				[]byte(fmt.Sprintf("payload-%02d", index)), time.Unix(1_800_100_000+int64(index), 0),
			)
			if err != nil {
				t.Fatal(err)
			}
			leaves = append(leaves, leaf)
		}
		root, err := BuildMerkleRoot(leaves)
		if err != nil {
			t.Fatal(err)
		}
		for index, leaf := range leaves {
			proof, err := BuildMerkleProof(leaves, index)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyMerkleProof(leaf, root, proof); err != nil {
				t.Fatalf("count=%d index=%d: %v", count, index, err)
			}

			if len(proof.Siblings) > 0 {
				tampered := proof
				tampered.Siblings = append([]ProofStep(nil), proof.Siblings...)
				tampered.Siblings[0].SHA256 = strings.Repeat("b", 64)
				if err := VerifyMerkleProof(leaf, root, tampered); !errors.Is(err, ErrInvalidProof) {
					t.Fatalf("count=%d index=%d tampered sibling accepted: %v", count, index, err)
				}
			} else {
				tamperedLeaf := leaf
				tamperedLeaf.Subject = "transfer:denied"
				if err := VerifyMerkleProof(tamperedLeaf, root, proof); !errors.Is(err, ErrInvalidProof) {
					t.Fatalf("single-leaf mutation accepted: %v", err)
				}
			}
		}
	}
}

func TestMerkleRootCommitsLeafOrderWhileSortedInputIsDeterministic(t *testing.T) {
	now := time.Unix(1_800_200_000, 0)
	first, _ := NewLeaf("a", "subject", "audit", []byte("one"), now)
	second, _ := NewLeaf("b", "subject", "audit", []byte("two"), now.Add(time.Second))
	forward, _ := BuildMerkleRoot([]Leaf{first, second})
	reverse, _ := BuildMerkleRoot([]Leaf{second, first})
	if forward == reverse {
		t.Fatal("Merkle root did not commit leaf order")
	}

	sortedA, _ := BuildMerkleRoot(SortLeaves([]Leaf{second, first}))
	sortedB, _ := BuildMerkleRoot(SortLeaves([]Leaf{first, second}))
	if sortedA != sortedB {
		t.Fatal("SortLeaves did not produce deterministic roots")
	}
}

func makeSignatureChain(t *testing.T, privateKey ed25519.PrivateKey, keyID string, count int) []SignedStatement {
	t.Helper()
	chain := make([]SignedStatement, 0, count)
	previous := ""
	for sequence := 1; sequence <= count; sequence++ {
		statement := Statement{
			Version: Version, StreamID: "audit/production", Sequence: uint64(sequence),
			PreviousSHA256: previous, MerkleRootSHA256: strings.Repeat("a", 64),
			LeafCount: 1, IssuedAtUnix: 1_800_000_000 + int64(sequence),
			SignerKeyID: keyID, Nonce: fmt.Sprintf("nonce-%d", sequence),
		}
		signed, err := SignStatementWithKey(statement, "ed25519", privateKey)
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
