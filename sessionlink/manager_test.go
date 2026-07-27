package sessionlink

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func testDescriptor() Descriptor {
	return Descriptor{
		ChainSHA256: strings.Repeat("a", 64),
		Topology:    []string{"workstation", "jump", "endpoint"},
		LocalNode:   "jump",
		PeerNode:    "endpoint",
	}
}

func TestDeriveIDStableAcrossEndpointOrder(t *testing.T) {
	left := testDescriptor()
	right := left
	right.LocalNode, right.PeerNode = right.PeerNode, right.LocalNode
	leftID, err := DeriveID(left)
	if err != nil {
		t.Fatal(err)
	}
	rightID, err := DeriveID(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftID != rightID {
		t.Fatalf("left=%s right=%s", leftID, rightID)
	}
}

func TestDeriveIDRejectsNonAdjacentNodes(t *testing.T) {
	descriptor := testDescriptor()
	descriptor.LocalNode = "workstation"
	if _, err := DeriveID(descriptor); !errors.Is(err, ErrInvalidDescriptor) {
		t.Fatalf("err=%v", err)
	}
}

func TestNewTransportIDUnique(t *testing.T) {
	left, err := NewTransportID()
	if err != nil {
		t.Fatal(err)
	}
	right, err := NewTransportID()
	if err != nil {
		t.Fatal(err)
	}
	if left == right || ValidateTransportID(left) != nil || ValidateTransportID(right) != nil {
		t.Fatalf("left=%q right=%q", left, right)
	}
}

func TestNewerGenerationFencesOldCleanup(t *testing.T) {
	manager := NewManager[string]()
	descriptor := testDescriptor()
	firstID, _ := NewTransportID()
	first, _, cleanupFirst, err := manager.Publish(descriptor, firstID, time.Minute, "first")
	if err != nil {
		t.Fatal(err)
	}
	secondID, _ := NewTransportID()
	second, _, cleanupSecond, err := manager.Publish(descriptor, secondID, time.Minute, "second")
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation != first.Generation+1 {
		t.Fatalf("first=%d second=%d", first.Generation, second.Generation)
	}
	cleanupFirst()
	value, snapshot, ok := manager.Current(second.LinkID)
	if !ok || value != "second" || snapshot.Generation != second.Generation {
		t.Fatalf("value=%q snapshot=%+v ok=%t", value, snapshot, ok)
	}
	cleanupSecond()
	if _, snapshot, ok := manager.Current(second.LinkID); ok || snapshot.State != StateDisconnected {
		t.Fatalf("snapshot=%+v ok=%t", snapshot, ok)
	}
}

func TestWaitReturnsAfterPublication(t *testing.T) {
	manager := NewManager[string]()
	descriptor := testDescriptor()
	id, err := DeriveID(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := make(chan string, 1)
	go func() {
		value, _, waitErr := manager.Wait(ctx, id)
		if waitErr != nil {
			result <- "error:" + waitErr.Error()
			return
		}
		result <- value
	}()
	time.Sleep(20 * time.Millisecond)
	transportID, _ := NewTransportID()
	if _, _, _, err := manager.Publish(descriptor, transportID, time.Second, "ready"); err != nil {
		t.Fatal(err)
	}
	select {
	case value := <-result:
		if value != "ready" {
			t.Fatal(value)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not return")
	}
}

func TestLeaseExpiryRemovesAvailability(t *testing.T) {
	manager := NewManager[string]()
	descriptor := testDescriptor()
	transportID, _ := NewTransportID()
	token, _, _, err := manager.Publish(descriptor, transportID, 30*time.Millisecond, "ready")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, snapshot, ok := manager.Current(token.LinkID); ok || snapshot.State != StateDisconnected || !strings.Contains(snapshot.LastError, "lease expired") {
		t.Fatalf("snapshot=%+v ok=%t", snapshot, ok)
	}
}

func TestOldFailureCannotWithdrawReplacement(t *testing.T) {
	manager := NewManager[string]()
	descriptor := testDescriptor()
	firstID, _ := NewTransportID()
	first, _, _, err := manager.Publish(descriptor, firstID, time.Minute, "first")
	if err != nil {
		t.Fatal(err)
	}
	secondID, _ := NewTransportID()
	second, _, _, err := manager.Publish(descriptor, secondID, time.Minute, "second")
	if err != nil {
		t.Fatal(err)
	}
	if manager.Withdraw(first, errors.New("old transport failed")) {
		t.Fatal("old transport withdrew replacement")
	}
	value, snapshot, ok := manager.Current(second.LinkID)
	if !ok || value != "second" || snapshot.Generation != second.Generation {
		t.Fatalf("value=%q snapshot=%+v ok=%t", value, snapshot, ok)
	}
}

func TestDrainStopsNewAcquisition(t *testing.T) {
	manager := NewManager[string]()
	descriptor := testDescriptor()
	transportID, _ := NewTransportID()
	token, _, _, err := manager.Publish(descriptor, transportID, time.Minute, "ready")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Drain(token); err != nil {
		t.Fatal(err)
	}
	if _, snapshot, ok := manager.Current(token.LinkID); ok || snapshot.State != StateDraining {
		t.Fatalf("snapshot=%+v ok=%t", snapshot, ok)
	}
}
