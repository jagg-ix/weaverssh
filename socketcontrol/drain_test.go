package socketcontrol

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestDrainActionIsAuthenticatedAndReplayProtected(t *testing.T) {
	token := bytes.Repeat([]byte{0x42}, 32)
	now := time.Unix(1_700_000_000, 0)
	request, err := NewRequest(ActionDrain, "", token, now)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Token: token}
	if err := server.verify(request, now); err != nil {
		t.Fatalf("drain request rejected: %v", err)
	}
	if err := server.verify(request, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed drain request returned %v", err)
	}
}
