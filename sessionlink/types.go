// Package sessionlink models stable logical adjacencies independently from
// disposable SSH/X11/WebSocket transports.
package sessionlink

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
)

const (
	IDVersion = "weaverssh.session-link.v1"
	MaxLease  = 24 * time.Hour
)

var (
	ErrInvalidDescriptor  = errors.New("sessionlink: invalid link descriptor")
	ErrInvalidTransport   = errors.New("sessionlink: invalid transport ID")
	ErrInvalidLease       = errors.New("sessionlink: invalid lease")
	ErrNotReady           = errors.New("sessionlink: logical link is not ready")
	ErrGenerationMismatch = errors.New("sessionlink: transport generation mismatch")
	ErrLeaseExpired       = errors.New("sessionlink: transport lease expired")
)

type ID string
type TransportID string

type State string

const (
	StateDisconnected State = "disconnected"
	StateConnecting   State = "connecting"
	StateReady        State = "ready"
	StateDraining     State = "draining"
)

type Descriptor struct {
	ChainSHA256 string
	Topology    []string
	LocalNode   string
	PeerNode    string
}

type Token struct {
	LinkID      ID
	TransportID TransportID
	Generation  uint64
}

type Snapshot struct {
	Version     string      `json:"version"`
	LinkID      ID          `json:"link_id"`
	TransportID TransportID `json:"transport_id,omitempty"`
	Generation  uint64      `json:"generation"`
	LocalNode   string      `json:"local_node,omitempty"`
	PeerNode    string      `json:"peer_node,omitempty"`
	State       State       `json:"state"`
	LastError   string      `json:"last_error,omitempty"`
	LeaseUntil  time.Time   `json:"lease_until,omitempty"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

func (s Snapshot) ReadyAt(now time.Time) bool {
	return s.State == StateReady && !s.LeaseUntil.IsZero() && now.Before(s.LeaseUntil)
}

func DeriveID(raw Descriptor) (ID, error) {
	descriptor, lower, upper, err := normalizeDescriptor(raw)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	for _, value := range []string{IDVersion, descriptor.ChainSHA256, lower, upper} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return ID(hex.EncodeToString(hash.Sum(nil))), nil
}

func NewTransportID() (TransportID, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return TransportID(base64.RawURLEncoding.EncodeToString(raw)), nil
}

func ValidateTransportID(id TransportID) error {
	value := strings.TrimSpace(string(id))
	if len(value) < 8 || len(value) > 512 {
		return ErrInvalidTransport
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return ErrInvalidTransport
		}
	}
	return nil
}

func ValidateID(id ID) error {
	value := string(id)
	if len(value) != sha256.Size*2 {
		return ErrInvalidDescriptor
	}
	if _, err := hex.DecodeString(value); err != nil || value != strings.ToLower(value) {
		return ErrInvalidDescriptor
	}
	return nil
}

func validateLease(lease time.Duration) error {
	if lease <= 0 || lease > MaxLease {
		return ErrInvalidLease
	}
	return nil
}

func normalizeDescriptor(raw Descriptor) (Descriptor, string, string, error) {
	out := raw
	out.ChainSHA256 = strings.ToLower(strings.TrimSpace(out.ChainSHA256))
	out.LocalNode = strings.TrimSpace(out.LocalNode)
	out.PeerNode = strings.TrimSpace(out.PeerNode)
	out.Topology = append([]string(nil), out.Topology...)
	if len(out.ChainSHA256) != sha256.Size*2 {
		return Descriptor{}, "", "", ErrInvalidDescriptor
	}
	if decoded, err := hex.DecodeString(out.ChainSHA256); err != nil || len(decoded) != sha256.Size {
		return Descriptor{}, "", "", ErrInvalidDescriptor
	}
	if !validNode(out.LocalNode) || !validNode(out.PeerNode) || out.LocalNode == out.PeerNode {
		return Descriptor{}, "", "", ErrInvalidDescriptor
	}
	if len(out.Topology) < 2 || len(out.Topology) > 1024 {
		return Descriptor{}, "", "", ErrInvalidDescriptor
	}
	seen := make(map[string]bool, len(out.Topology))
	localIndex, peerIndex := -1, -1
	for index, rawNode := range out.Topology {
		node := strings.TrimSpace(rawNode)
		if !validNode(node) || seen[node] {
			return Descriptor{}, "", "", ErrInvalidDescriptor
		}
		seen[node] = true
		out.Topology[index] = node
		if node == out.LocalNode {
			localIndex = index
		}
		if node == out.PeerNode {
			peerIndex = index
		}
	}
	if localIndex < 0 || peerIndex < 0 || abs(localIndex-peerIndex) != 1 {
		return Descriptor{}, "", "", fmt.Errorf("%w: nodes are not adjacent", ErrInvalidDescriptor)
	}
	lower, upper := out.LocalNode, out.PeerNode
	if localIndex > peerIndex {
		lower, upper = upper, lower
	}
	return out, lower, upper, nil
}

func validNode(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func abs(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
