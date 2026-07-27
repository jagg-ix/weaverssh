package authproof

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Schema                 string      `json:"schema"`
	TargetCodes            []string    `json:"target_codes"`
	SeedHex                string      `json:"seed_hex"`
	PublicKeyBase64URL     string      `json:"public_key_base64url"`
	CanonicalPayload       string      `json:"canonical_payload"`
	CanonicalPayloadSHA256 string      `json:"canonical_payload_sha256"`
	SignedGrant            SignedGrant `json:"signed_grant"`
}

func loadVector(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join("testdata", "weaverssh_authproof_v1_vector.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("decode vector: %v", err)
	}
	return v
}

func vectorKeys(t *testing.T, v vectorFile) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	seed, err := hex.DecodeString(v.SeedHex)
	if err != nil {
		t.Fatalf("decode seed: %v", err)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey, err := DecodePublicKey(v.PublicKeyBase64URL)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if !ed25519.PublicKey(privateKey.Public().(ed25519.PublicKey)).Equal(publicKey) {
		t.Fatalf("public key does not match seed")
	}
	return privateKey, publicKey
}

func vectorVerifyOptions(v vectorFile) VerifyOptions {
	return VerifyOptions{
		Now:                  time.Unix(1781234590, 0),
		Audience:             "wv-agent",
		SubjectPeerID:        "agent-linode-a",
		RequiredCapabilities: []string{CapabilityWebSocketUpgrade, CapabilityX11Relay},
		X11CookieSHA256:      v.SignedGrant.Grant.X11CookieSHA256,
		ChainSHA256:          v.SignedGrant.Grant.ChainSHA256,
		ReplayCache:          NewNonceCache(),
	}
}


func TestCanonicalPayloadMatchesVector(t *testing.T) {
	v := loadVector(t)
	canonical, err := CanonicalBytes(v.SignedGrant.Grant)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(canonical) != v.CanonicalPayload {
		t.Fatalf("canonical payload mismatch\nwant: %s\n got: %s", v.CanonicalPayload, string(canonical))
	}
	if SHA256Hex(canonical) != v.CanonicalPayloadSHA256 {
		t.Fatalf("canonical payload hash mismatch")
	}
}

func TestSignGrantMatchesVector(t *testing.T) {
	v := loadVector(t)
	privateKey, _ := vectorKeys(t, v)
	signed, err := SignGrant(v.SignedGrant.Grant, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signed.Signature != v.SignedGrant.Signature {
		t.Fatalf("signature mismatch\nwant: %s\n got: %s", v.SignedGrant.Signature, signed.Signature)
	}
}

func TestGrantRejectsUnknownSecurityLevel(t *testing.T) {
	v := loadVector(t)
	grant := v.SignedGrant.Grant
	grant.SecurityLevel = "unknown-level"
	_, err := CanonicalBytes(grant)
	if !errors.Is(err, ErrInvalidSecurityLevel) {
		t.Fatalf("expected ErrInvalidSecurityLevel, got %v", err)
	}
}

func TestVerifySignedGrantAcceptsVector(t *testing.T) {
	v := loadVector(t)
	_, publicKey := vectorKeys(t, v)
	grant, err := VerifySignedGrant(v.SignedGrant, publicKey, vectorVerifyOptions(v))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if grant.SessionID != "session-20260612-target-001-002" {
		t.Fatalf("wrong session id: %s", grant.SessionID)
	}
}

func TestVerifySignedGrantRejectsForgedSignature(t *testing.T) {
	v := loadVector(t)
	_, publicKey := vectorKeys(t, v)
	forged := v.SignedGrant
	forged.Signature = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, err := VerifySignedGrant(forged, publicKey, vectorVerifyOptions(v))
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestVerifySignedGrantRejectsExpired(t *testing.T) {
	v := loadVector(t)
	_, publicKey := vectorKeys(t, v)
	opts := vectorVerifyOptions(v)
	opts.Now = time.Unix(v.SignedGrant.Grant.ExpiresAtUnix, 0)
	_, err := VerifySignedGrant(v.SignedGrant, publicKey, opts)
	if !errors.Is(err, ErrExpiredGrant) {
		t.Fatalf("expected ErrExpiredGrant, got %v", err)
	}
}

func TestVerifySignedGrantRejectsWrongAudience(t *testing.T) {
	v := loadVector(t)
	_, publicKey := vectorKeys(t, v)
	opts := vectorVerifyOptions(v)
	opts.Audience = "wv-socks"
	_, err := VerifySignedGrant(v.SignedGrant, publicKey, opts)
	if !errors.Is(err, ErrWrongAudience) {
		t.Fatalf("expected ErrWrongAudience, got %v", err)
	}
}

func TestVerifySignedGrantRejectsMissingCapability(t *testing.T) {
	v := loadVector(t)
	_, publicKey := vectorKeys(t, v)
	opts := vectorVerifyOptions(v)
	opts.RequiredCapabilities = []string{CapabilityFileBackhaul}
	_, err := VerifySignedGrant(v.SignedGrant, publicKey, opts)
	if !errors.Is(err, ErrMissingCapability) {
		t.Fatalf("expected ErrMissingCapability, got %v", err)
	}
}

func TestVerifySignedGrantRejectsWrongX11CookieHash(t *testing.T) {
	v := loadVector(t)
	_, publicKey := vectorKeys(t, v)
	opts := vectorVerifyOptions(v)
	opts.X11CookieSHA256 = SHA256Hex([]byte("different-cookie"))
	_, err := VerifySignedGrant(v.SignedGrant, publicKey, opts)
	if !errors.Is(err, ErrWrongX11CookieHash) {
		t.Fatalf("expected ErrWrongX11CookieHash, got %v", err)
	}
}

func TestVerifySignedGrantRejectsWrongChainHash(t *testing.T) {
	v := loadVector(t)
	_, publicKey := vectorKeys(t, v)
	opts := vectorVerifyOptions(v)
	opts.ChainSHA256 = SHA256Hex([]byte("different-chain"))
	_, err := VerifySignedGrant(v.SignedGrant, publicKey, opts)
	if !errors.Is(err, ErrWrongChainHash) {
		t.Fatalf("expected ErrWrongChainHash, got %v", err)
	}
}

func TestVerifySignedGrantRejectsReplay(t *testing.T) {
	v := loadVector(t)
	_, publicKey := vectorKeys(t, v)
	opts := vectorVerifyOptions(v)
	if _, err := VerifySignedGrant(v.SignedGrant, publicKey, opts); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	_, err := VerifySignedGrant(v.SignedGrant, publicKey, opts)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("expected ErrReplay, got %v", err)
	}
}

func TestNormalizeSortsAndDeduplicatesCapabilitiesBeforeSigning(t *testing.T) {
	v := loadVector(t)
	privateKey, _ := vectorKeys(t, v)
	grant := v.SignedGrant.Grant
	grant.Capabilities = []string{CapabilityX11Relay, CapabilityWebSocketUpgrade, CapabilityX11Relay}
	signed, err := SignGrant(grant, privateKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if got, want := signed.Grant.Capabilities, []string{CapabilityWebSocketUpgrade, CapabilityX11Relay}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("capabilities not canonical: %v", got)
	}
	if signed.Signature != v.SignedGrant.Signature {
		t.Fatalf("normalization changed signature: %s", signed.Signature)
	}
}

func TestControlFrameRoundTripAndTypeCheck(t *testing.T) {
	v := loadVector(t)
	data, err := MarshalControlFrame(v.SignedGrant)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	parsed, err := ParseControlFrame(data)
	if err != nil {
		t.Fatalf("parse frame: %v", err)
	}
	if parsed.Signature != v.SignedGrant.Signature {
		t.Fatalf("signature mismatch after frame round trip")
	}
	bad := strings.Replace(string(data), Version, "other.type", 1)
	_, err = ParseControlFrame([]byte(bad))
	if !errors.Is(err, ErrWrongFrameType) {
		t.Fatalf("expected ErrWrongFrameType, got %v", err)
	}
}

func TestDecodePrivateKeyAcceptsSeedAndFullPrivateKey(t *testing.T) {
	v := loadVector(t)
	seedPrivate, publicKey := vectorKeys(t, v)
	fromSeed, err := DecodePrivateKey(v.SeedHex)
	if err != nil {
		t.Fatalf("decode seed private key: %v", err)
	}
	fromFull, err := DecodePrivateKey(EncodePrivateKey(seedPrivate))
	if err != nil {
		t.Fatalf("decode full private key: %v", err)
	}
	if !fromSeed.Public().(ed25519.PublicKey).Equal(publicKey) {
		t.Fatalf("seed private key public key mismatch")
	}
	if !fromFull.Public().(ed25519.PublicKey).Equal(publicKey) {
		t.Fatalf("full private key public key mismatch")
	}
}
