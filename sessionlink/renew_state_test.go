package sessionlink

import (
	"errors"
	"testing"
	"time"
)

func TestRenewRejectsDisconnectedGeneration(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	manager := NewManagerWithClock[string](func() time.Time { return now })
	transportID, err := NewTransportID()
	if err != nil {
		t.Fatal(err)
	}
	token, before, _, err := manager.Publish(testDescriptor(), transportID, time.Minute, "ready")
	if err != nil {
		t.Fatal(err)
	}
	if !manager.Withdraw(token, errors.New("transport ended")) {
		t.Fatal("withdraw failed")
	}
	disconnected, ok := manager.Snapshot(token.LinkID)
	if !ok || disconnected.State != StateDisconnected {
		t.Fatalf("snapshot=%+v ok=%t", disconnected, ok)
	}
	now = now.Add(10 * time.Second)
	after, err := manager.Renew(token, time.Minute)
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("renew error=%v", err)
	}
	if !after.LeaseUntil.Equal(disconnected.LeaseUntil) || after.LeaseUntil.Equal(now.Add(time.Minute)) {
		t.Fatalf("renew extended disconnected lease: before=%s disconnected=%s after=%s", before.LeaseUntil, disconnected.LeaseUntil, after.LeaseUntil)
	}
}
