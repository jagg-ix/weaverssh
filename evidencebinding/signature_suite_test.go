package evidencebinding

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func TestSignatureSuiteSupportsRSAECDSAAndEd25519(t *testing.T) {
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edTrusted, err := NewTrustedSigner("ed25519", edPublic)
	if err != nil {
		t.Fatal(err)
	}
	rsaPrivate, rsaTrusted, err := GenerateRSAPSSSigner(2048)
	if err != nil {
		t.Fatal(err)
	}
	p256Private, p256Trusted, err := GenerateECDSASigner(AlgorithmECDSAP256SHA256)
	if err != nil {
		t.Fatal(err)
	}
	p384Private, p384Trusted, err := GenerateECDSASigner(AlgorithmECDSAP384SHA384)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, algorithm string
		private         any
		trusted         TrustedSigner
	}{
		{"Ed25519", "ed25519", edPrivate, edTrusted},
		{"RSA-PSS", AlgorithmRSAPSSSHA256, rsaPrivate, rsaTrusted},
		{"ECDSA-P256", AlgorithmECDSAP256SHA256, p256Private, p256Trusted},
		{"ECDSA-P384", AlgorithmECDSAP384SHA384, p384Private, p384Trusted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy, err := NewSignatureTrustPolicy([]TrustedSigner{tc.trusted})
			if err != nil {
				t.Fatal(err)
			}
			statement := signatureTestStatement(tc.trusted.KeyID)
			signed, err := SignStatementWithKey(statement, tc.algorithm, tc.private)
			if err != nil {
				t.Fatal(err)
			}
			if err := policy.Verify(signed); err != nil {
				t.Fatalf("verify: %v", err)
			}
			report, err := VerifyLedgerWithSignaturePolicy([]SignedStatement{signed}, policy, VerifyOptions{ExpectedStreamID: "audit/production"})
			if err != nil || !report.Authentic {
				t.Fatalf("ledger report=%+v err=%v", report, err)
			}
		})
	}
}

func TestSignatureSuiteRejectsMutationSubstitutionAndAlgorithmConfusion(t *testing.T) {
	rsaPrivate, rsaTrusted, _ := GenerateRSAPSSSigner(2048)
	_, rogueTrusted, _ := GenerateRSAPSSSigner(2048)
	policy, _ := NewSignatureTrustPolicy([]TrustedSigner{rsaTrusted})
	signed, _ := SignStatementWithKey(signatureTestStatement(rsaTrusted.KeyID), AlgorithmRSAPSSSHA256, rsaPrivate)

	mutated := signed
	mutated.Statement.Nonce = "changed"
	if err := policy.Verify(mutated); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("mutation err=%v", err)
	}

	substituted := signed
	substituted.PublicKey = base64.RawURLEncoding.EncodeToString(rogueTrusted.PublicKey)
	if err := policy.Verify(substituted); !errors.Is(err, ErrUntrustedSigner) {
		t.Fatalf("substitution err=%v", err)
	}

	confused := signed
	confused.Algorithm = AlgorithmECDSAP256SHA256
	if err := policy.Verify(confused); !errors.Is(err, ErrSignatureAlgorithmMismatch) {
		t.Fatalf("confusion err=%v", err)
	}

	damaged := signed
	sig, _ := base64.RawURLEncoding.DecodeString(damaged.Signature)
	sig[len(sig)-1] ^= 1
	damaged.Signature = base64.RawURLEncoding.EncodeToString(sig)
	if err := policy.Verify(damaged); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("damaged signature err=%v", err)
	}
}

func TestSignatureSuiteRejectsWeakRSAAndWrongECDSACurve(t *testing.T) {
	if _, _, err := GenerateRSAPSSSigner(1024); !errors.Is(err, ErrWeakSignatureKey) {
		t.Fatalf("weak RSA err=%v", err)
	}
	p384Private, p384Trusted, _ := GenerateECDSASigner(AlgorithmECDSAP384SHA384)
	statement := signatureTestStatement(p384Trusted.KeyID)
	if _, err := SignStatementWithKey(statement, AlgorithmECDSAP256SHA256, p384Private); !errors.Is(err, ErrSignatureAlgorithmMismatch) {
		t.Fatalf("wrong curve err=%v", err)
	}
}

func signatureTestStatement(keyID string) Statement {
	return Statement{Version: Version, StreamID: "audit/production", Sequence: 1, MerkleRootSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", LeafCount: 1, IssuedAtUnix: 1_800_000_000, SignerKeyID: keyID, Nonce: "nonce-1"}
}
