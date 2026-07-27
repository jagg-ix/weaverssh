package socksproof

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	DatagramSessionProtocol       = "weaverssh.socks-datagram-session.v1"
	MaxAuthenticatedDatagramBytes = 65507
	maxResponseMetadataBytes      = 12 << 10
)

// DatagramSession carries a random response-authentication key over the already
// authenticated SOCKS TCP control connection. It is emitted only after the
// client requested UDP ASSOCIATE, so CONNECT and BIND wire compatibility is not
// affected. The key provides integrity and replay protection for proxy-to-client
// UDP responses; it does not provide payload confidentiality.
type DatagramSession struct {
	Protocol        string `json:"protocol"`
	ChallengeSHA256 string `json:"challenge_sha256"`
	SessionBinding  string `json:"session_binding"`
	SelectedNode    string `json:"selected_node"`
	Key             string `json:"key"`
	ExpiresAtUnix   int64  `json:"expires_at_unix"`
}

// DatagramResponseStatement authenticates one proxy-to-client RFC 1928 packet.
type DatagramResponseStatement struct {
	Protocol        string `json:"protocol"`
	ChallengeSHA256 string `json:"challenge_sha256"`
	SessionBinding  string `json:"session_binding"`
	SelectedNode    string `json:"selected_node"`
	Sequence        uint64 `json:"sequence"`
	PayloadSHA256   string `json:"payload_sha256"`
	IssuedAtUnix    int64  `json:"issued_at_unix"`
	ExpiresAtUnix   int64  `json:"expires_at_unix"`
}

type AuthenticatedDatagramResponse struct {
	Statement DatagramResponseStatement `json:"statement"`
	MAC       string                    `json:"mac"`
}

// SequenceWindow accepts new or out-of-order sequence numbers within a 64-item
// window and rejects duplicates or values older than the retained window.
type SequenceWindow struct {
	mu      sync.Mutex
	highest uint64
	bitmap  uint64
}

func (w *SequenceWindow) Accept(sequence uint64) bool {
	if w == nil || sequence == 0 {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.highest == 0 {
		w.highest = sequence
		w.bitmap = 1
		return true
	}
	if sequence > w.highest {
		shift := sequence - w.highest
		if shift >= 64 {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.highest = sequence
		w.bitmap |= 1
		return true
	}
	distance := w.highest - sequence
	if distance >= 64 {
		return false
	}
	mask := uint64(1) << distance
	if w.bitmap&mask != 0 {
		return false
	}
	w.bitmap |= mask
	return true
}

func NewDatagramSession(challenge Challenge, now time.Time) (DatagramSession, []byte, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(challenge, now); err != nil {
		return DatagramSession{}, nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return DatagramSession{}, nil, err
	}
	session := DatagramSession{
		Protocol:        DatagramSessionProtocol,
		ChallengeSHA256: DigestChallenge(challenge),
		SessionBinding:  challenge.SessionBinding,
		SelectedNode:    challenge.SelectedNode,
		Key:             base64.RawURLEncoding.EncodeToString(key),
		ExpiresAtUnix:   challenge.ExpiresAtUnix,
	}
	return session, key, nil
}

func (s DatagramSession) ResponseKey(challenge Challenge, now time.Time) ([]byte, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(challenge, now); err != nil {
		return nil, err
	}
	if s.Protocol != DatagramSessionProtocol ||
		s.ChallengeSHA256 != DigestChallenge(challenge) ||
		s.SessionBinding != challenge.SessionBinding ||
		s.SelectedNode != challenge.SelectedNode ||
		s.ExpiresAtUnix != challenge.ExpiresAtUnix ||
		now.Unix() >= s.ExpiresAtUnix {
		return nil, ErrInvalidProof
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(s.Key))
	if err != nil || len(key) != 32 {
		return nil, ErrInvalidProof
	}
	return key, nil
}

func EncodeDatagramResponse(key []byte, challenge Challenge, sequence uint64, packet []byte, now time.Time) ([]byte, error) {
	if len(key) != 32 || sequence == 0 || len(packet) == 0 {
		return nil, ErrInvalidProof
	}
	if now.IsZero() {
		now = time.Now()
	}
	if err := validateChallenge(challenge, now); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(packet)
	statement := DatagramResponseStatement{
		Protocol:        DatagramSessionProtocol,
		ChallengeSHA256: DigestChallenge(challenge),
		SessionBinding:  challenge.SessionBinding,
		SelectedNode:    challenge.SelectedNode,
		Sequence:        sequence,
		PayloadSHA256:   hex.EncodeToString(sum[:]),
		IssuedAtUnix:    now.Unix(),
		ExpiresAtUnix:   challenge.ExpiresAtUnix,
	}
	mac, err := datagramResponseMAC(key, statement)
	if err != nil {
		return nil, err
	}
	metadata, err := json.Marshal(AuthenticatedDatagramResponse{Statement: statement, MAC: mac})
	if err != nil {
		return nil, err
	}
	if len(metadata) == 0 || len(metadata) > maxResponseMetadataBytes || 4+len(metadata)+len(packet) > MaxAuthenticatedDatagramBytes {
		return nil, ErrInvalidProof
	}
	out := make([]byte, 4+len(metadata)+len(packet))
	binary.BigEndian.PutUint32(out[:4], uint32(len(metadata)))
	copy(out[4:], metadata)
	copy(out[4+len(metadata):], packet)
	return out, nil
}

func DecodeDatagramResponse(raw, key []byte, challenge Challenge, now time.Time) (AuthenticatedDatagramResponse, []byte, error) {
	if len(key) != 32 || len(raw) < 5 || len(raw) > MaxAuthenticatedDatagramBytes {
		return AuthenticatedDatagramResponse{}, nil, ErrInvalidProof
	}
	if now.IsZero() {
		now = time.Now()
	}
	metadataLength := int(binary.BigEndian.Uint32(raw[:4]))
	if metadataLength <= 0 || metadataLength > maxResponseMetadataBytes || 4+metadataLength >= len(raw) {
		return AuthenticatedDatagramResponse{}, nil, ErrInvalidProof
	}
	var response AuthenticatedDatagramResponse
	decoder := json.NewDecoder(bytes.NewReader(raw[4 : 4+metadataLength]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return AuthenticatedDatagramResponse{}, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return AuthenticatedDatagramResponse{}, nil, ErrInvalidProof
	}
	statement := response.Statement
	if statement.Protocol != DatagramSessionProtocol ||
		statement.ChallengeSHA256 != DigestChallenge(challenge) ||
		statement.SessionBinding != challenge.SessionBinding ||
		statement.SelectedNode != challenge.SelectedNode ||
		statement.Sequence == 0 ||
		statement.IssuedAtUnix < challenge.IssuedAtUnix ||
		statement.ExpiresAtUnix != challenge.ExpiresAtUnix ||
		now.Unix() < statement.IssuedAtUnix || now.Unix() >= statement.ExpiresAtUnix {
		return AuthenticatedDatagramResponse{}, nil, ErrInvalidProof
	}
	if !verifyDatagramResponseMAC(key, statement, response.MAC) {
		return AuthenticatedDatagramResponse{}, nil, ErrUnauthorized
	}
	packet := append([]byte(nil), raw[4+metadataLength:]...)
	sum := sha256.Sum256(packet)
	if statement.PayloadSHA256 != hex.EncodeToString(sum[:]) {
		return AuthenticatedDatagramResponse{}, nil, ErrInvalidProof
	}
	return response, packet, nil
}

func datagramResponseMAC(key []byte, statement DatagramResponseStatement) (string, error) {
	payload, err := canonical(statement)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func verifyDatagramResponseMAC(key []byte, statement DatagramResponseStatement, encoded string) bool {
	expected, err := datagramResponseMAC(key, statement)
	if err != nil {
		return false
	}
	expectedBytes, _ := hex.DecodeString(expected)
	provided, err := hex.DecodeString(strings.TrimSpace(encoded))
	return err == nil && hmac.Equal(expectedBytes, provided)
}
