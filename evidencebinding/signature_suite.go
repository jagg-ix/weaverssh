package evidencebinding

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	AlgorithmRSAPSSSHA256    = "rsa-pss-sha256"
	AlgorithmECDSAP256SHA256 = "ecdsa-p256-sha256"
	AlgorithmECDSAP384SHA384 = "ecdsa-p384-sha384"
)

var (
	ErrUnsupportedSignatureAlgorithm = errors.New("unsupported evidence signature algorithm")
	ErrSignatureAlgorithmMismatch    = errors.New("evidence signature algorithm does not match key")
	ErrWeakSignatureKey              = errors.New("evidence signature key does not meet minimum strength")
)

type TrustedSigner struct {
	KeyID     string
	Algorithm string
	PublicKey []byte
}

type SignatureTrustPolicy struct {
	keys map[string]TrustedSigner
}

func NewTrustedSigner(algorithm string, publicKey any) (TrustedSigner, error) {
	algorithm = normalizeSignatureAlgorithm(algorithm)
	encoded, err := encodeSignaturePublicKey(algorithm, publicKey)
	if err != nil {
		return TrustedSigner{}, err
	}
	return TrustedSigner{
		KeyID: SignatureKeyID(algorithm, encoded), Algorithm: algorithm,
		PublicKey: append([]byte(nil), encoded...),
	}, nil
}

func NewSignatureTrustPolicy(entries []TrustedSigner) (SignatureTrustPolicy, error) {
	policy := SignatureTrustPolicy{keys: make(map[string]TrustedSigner, len(entries))}
	for _, entry := range entries {
		entry.Algorithm = normalizeSignatureAlgorithm(entry.Algorithm)
		if entry.KeyID == "" || len(entry.PublicKey) == 0 {
			return SignatureTrustPolicy{}, ErrUntrustedSigner
		}
		if _, err := parseSignaturePublicKey(entry.Algorithm, entry.PublicKey); err != nil {
			return SignatureTrustPolicy{}, err
		}
		if entry.KeyID != SignatureKeyID(entry.Algorithm, entry.PublicKey) {
			return SignatureTrustPolicy{}, fmt.Errorf("%w: key id mismatch", ErrUntrustedSigner)
		}
		if _, exists := policy.keys[entry.KeyID]; exists {
			return SignatureTrustPolicy{}, fmt.Errorf("%w: duplicate key id %s", ErrUntrustedSigner, entry.KeyID)
		}
		entry.PublicKey = append([]byte(nil), entry.PublicKey...)
		policy.keys[entry.KeyID] = entry
	}
	return policy, nil
}

func SignatureKeyID(algorithm string, encodedPublicKey []byte) string {
	sum := sha256.Sum256(encodedPublicKey)
	return normalizeSignatureAlgorithm(algorithm) + ":" + hex.EncodeToString(sum[:])
}

func GenerateRSAPSSSigner(bits int) (*rsa.PrivateKey, TrustedSigner, error) {
	if bits < 2048 {
		return nil, TrustedSigner{}, ErrWeakSignatureKey
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, TrustedSigner{}, err
	}
	trusted, err := NewTrustedSigner(AlgorithmRSAPSSSHA256, &privateKey.PublicKey)
	return privateKey, trusted, err
}

func GenerateECDSASigner(algorithm string) (*ecdsa.PrivateKey, TrustedSigner, error) {
	algorithm = normalizeSignatureAlgorithm(algorithm)
	var curve elliptic.Curve
	switch algorithm {
	case AlgorithmECDSAP256SHA256:
		curve = elliptic.P256()
	case AlgorithmECDSAP384SHA384:
		curve = elliptic.P384()
	default:
		return nil, TrustedSigner{}, ErrUnsupportedSignatureAlgorithm
	}
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, TrustedSigner{}, err
	}
	trusted, err := NewTrustedSigner(algorithm, &privateKey.PublicKey)
	return privateKey, trusted, err
}

func SignStatementWithKey(statement Statement, algorithm string, privateKey any) (SignedStatement, error) {
	algorithm = normalizeSignatureAlgorithm(algorithm)
	publicKey, err := signaturePublicFromPrivate(algorithm, privateKey)
	if err != nil {
		return SignedStatement{}, err
	}
	encodedPublicKey, err := encodeSignaturePublicKey(algorithm, publicKey)
	if err != nil {
		return SignedStatement{}, err
	}
	if statement.SignerKeyID != SignatureKeyID(algorithm, encodedPublicKey) {
		return SignedStatement{}, fmt.Errorf("%w: signer key id does not match private key", ErrInvalidEvidence)
	}
	canonical, err := statement.canonicalBytes()
	if err != nil {
		return SignedStatement{}, err
	}
	message := append([]byte(statementDomain), canonical...)
	signature, err := signStatementMessage(algorithm, privateKey, message)
	if err != nil {
		return SignedStatement{}, err
	}
	return SignedStatement{
		Statement: statement, Algorithm: algorithm,
		PublicKey: base64.RawURLEncoding.EncodeToString(encodedPublicKey),
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func (p SignatureTrustPolicy) Verify(signed SignedStatement) error {
	algorithm := normalizeSignatureAlgorithm(signed.Algorithm)
	trusted, ok := p.keys[signed.Statement.SignerKeyID]
	if !ok {
		return ErrUntrustedSigner
	}
	if trusted.Algorithm != algorithm {
		return ErrSignatureAlgorithmMismatch
	}
	embedded, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signed.PublicKey))
	if err != nil || !bytes.Equal(embedded, trusted.PublicKey) {
		return ErrUntrustedSigner
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(signed.Signature))
	if err != nil {
		return ErrInvalidSignature
	}
	canonical, err := signed.Statement.canonicalBytes()
	if err != nil {
		return err
	}
	message := append([]byte(statementDomain), canonical...)
	publicKey, err := parseSignaturePublicKey(algorithm, trusted.PublicKey)
	if err != nil {
		return err
	}
	if err := verifyStatementMessage(algorithm, publicKey, message, signature); err != nil {
		return err
	}
	return nil
}

func VerifyLedgerWithSignaturePolicy(statements []SignedStatement, trust SignatureTrustPolicy, options VerifyOptions) (VerificationReport, error) {
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

func normalizeSignatureAlgorithm(algorithm string) string {
	return strings.ToLower(strings.TrimSpace(algorithm))
}

func encodeSignaturePublicKey(algorithm string, publicKey any) ([]byte, error) {
	switch normalizeSignatureAlgorithm(algorithm) {
	case "ed25519":
		key, ok := publicKey.(ed25519.PublicKey)
		if !ok || len(key) != ed25519.PublicKeySize {
			return nil, ErrSignatureAlgorithmMismatch
		}
		return append([]byte(nil), key...), nil
	case AlgorithmRSAPSSSHA256:
		key, ok := publicKey.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 2048 {
			if ok {
				return nil, ErrWeakSignatureKey
			}
			return nil, ErrSignatureAlgorithmMismatch
		}
		return x509.MarshalPKIXPublicKey(key)
	case AlgorithmECDSAP256SHA256, AlgorithmECDSAP384SHA384:
		key, ok := publicKey.(*ecdsa.PublicKey)
		if !ok || !curveMatchesAlgorithm(key.Curve, algorithm) {
			return nil, ErrSignatureAlgorithmMismatch
		}
		return x509.MarshalPKIXPublicKey(key)
	default:
		return nil, ErrUnsupportedSignatureAlgorithm
	}
}

func parseSignaturePublicKey(algorithm string, encoded []byte) (any, error) {
	switch normalizeSignatureAlgorithm(algorithm) {
	case "ed25519":
		if len(encoded) != ed25519.PublicKeySize {
			return nil, ErrSignatureAlgorithmMismatch
		}
		return ed25519.PublicKey(append([]byte(nil), encoded...)), nil
	case AlgorithmRSAPSSSHA256:
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		if err != nil {
			return nil, ErrSignatureAlgorithmMismatch
		}
		key, ok := parsed.(*rsa.PublicKey)
		if !ok || key.N.BitLen() < 2048 {
			if ok {
				return nil, ErrWeakSignatureKey
			}
			return nil, ErrSignatureAlgorithmMismatch
		}
		return key, nil
	case AlgorithmECDSAP256SHA256, AlgorithmECDSAP384SHA384:
		parsed, err := x509.ParsePKIXPublicKey(encoded)
		if err != nil {
			return nil, ErrSignatureAlgorithmMismatch
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok || !curveMatchesAlgorithm(key.Curve, algorithm) {
			return nil, ErrSignatureAlgorithmMismatch
		}
		return key, nil
	default:
		return nil, ErrUnsupportedSignatureAlgorithm
	}
}

func signaturePublicFromPrivate(algorithm string, privateKey any) (any, error) {
	switch normalizeSignatureAlgorithm(algorithm) {
	case "ed25519":
		key, ok := privateKey.(ed25519.PrivateKey)
		if !ok || len(key) != ed25519.PrivateKeySize {
			return nil, ErrSignatureAlgorithmMismatch
		}
		return key.Public().(ed25519.PublicKey), nil
	case AlgorithmRSAPSSSHA256:
		key, ok := privateKey.(*rsa.PrivateKey)
		if !ok || key.N.BitLen() < 2048 {
			if ok {
				return nil, ErrWeakSignatureKey
			}
			return nil, ErrSignatureAlgorithmMismatch
		}
		return &key.PublicKey, nil
	case AlgorithmECDSAP256SHA256, AlgorithmECDSAP384SHA384:
		key, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok || !curveMatchesAlgorithm(key.Curve, algorithm) {
			return nil, ErrSignatureAlgorithmMismatch
		}
		return &key.PublicKey, nil
	default:
		return nil, ErrUnsupportedSignatureAlgorithm
	}
}

func signStatementMessage(algorithm string, privateKey any, message []byte) ([]byte, error) {
	switch normalizeSignatureAlgorithm(algorithm) {
	case "ed25519":
		key := privateKey.(ed25519.PrivateKey)
		return ed25519.Sign(key, message), nil
	case AlgorithmRSAPSSSHA256:
		digest := sha256.Sum256(message)
		return rsa.SignPSS(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA256, digest[:], nil)
	case AlgorithmECDSAP256SHA256:
		digest := sha256.Sum256(message)
		return ecdsa.SignASN1(rand.Reader, privateKey.(*ecdsa.PrivateKey), digest[:])
	case AlgorithmECDSAP384SHA384:
		digest := sha512.Sum384(message)
		return ecdsa.SignASN1(rand.Reader, privateKey.(*ecdsa.PrivateKey), digest[:])
	default:
		return nil, ErrUnsupportedSignatureAlgorithm
	}
}

func verifyStatementMessage(algorithm string, publicKey any, message, signature []byte) error {
	switch normalizeSignatureAlgorithm(algorithm) {
	case "ed25519":
		if !ed25519.Verify(publicKey.(ed25519.PublicKey), message, signature) {
			return ErrInvalidSignature
		}
	case AlgorithmRSAPSSSHA256:
		digest := sha256.Sum256(message)
		if err := rsa.VerifyPSS(publicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], signature, nil); err != nil {
			return ErrInvalidSignature
		}
	case AlgorithmECDSAP256SHA256:
		digest := sha256.Sum256(message)
		if !ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), digest[:], signature) {
			return ErrInvalidSignature
		}
	case AlgorithmECDSAP384SHA384:
		digest := sha512.Sum384(message)
		if !ecdsa.VerifyASN1(publicKey.(*ecdsa.PublicKey), digest[:], signature) {
			return ErrInvalidSignature
		}
	default:
		return ErrUnsupportedSignatureAlgorithm
	}
	return nil
}

func curveMatchesAlgorithm(curve elliptic.Curve, algorithm string) bool {
	if curve == nil {
		return false
	}
	switch normalizeSignatureAlgorithm(algorithm) {
	case AlgorithmECDSAP256SHA256:
		return curve.Params().Name == elliptic.P256().Params().Name
	case AlgorithmECDSAP384SHA384:
		return curve.Params().Name == elliptic.P384().Params().Name
	default:
		return false
	}
}
