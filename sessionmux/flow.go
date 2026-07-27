package sessionmux

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// DefaultInitialWindow bounds unread bytes buffered for one stream in one
	// direction. Credit is returned only after the application consumes data.
	DefaultInitialWindow uint32 = 256 << 10
	// DefaultMaxDataPayload limits one DATA frame independently of the codec's
	// absolute frame-payload ceiling.
	DefaultMaxDataPayload uint32 = 64 << 10
	// maxInitialWindow bounds both locally configured and peer-advertised initial
	// credit. It is a protocol safety ceiling, not an eager allocation.
	maxInitialWindow uint32 = 64 << 20
)

var (
	// ErrFlowControlViolation reports peer data or credit that violates the
	// negotiated per-stream window.
	ErrFlowControlViolation = errors.New("sessionmux: flow-control violation")
)

func encodeWindowCredit(credit uint32) ([]byte, error) {
	if credit == 0 {
		return nil, fmt.Errorf("%w: zero WINDOW credit", ErrFlowControlViolation)
	}
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, credit)
	return payload, nil
}

func decodeWindowCredit(payload []byte) (uint32, error) {
	if len(payload) != 4 {
		return 0, fmt.Errorf("%w: WINDOW payload length %d", ErrFlowControlViolation, len(payload))
	}
	credit := binary.BigEndian.Uint32(payload)
	if credit == 0 {
		return 0, fmt.Errorf("%w: zero WINDOW credit", ErrFlowControlViolation)
	}
	return credit, nil
}

func minUint32(left, right uint32) uint32 {
	if left < right {
		return left
	}
	return right
}
