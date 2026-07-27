package app

import (
	"errors"
	"testing"
	"time"
)

func TestGenerationHandoverSerializesPublication(t *testing.T) {
	var handover generationHandover[int]
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{})
	firstResult := make(chan int, 1)
	secondResult := make(chan int, 1)

	go func() {
		previous, err := handover.Commit(1, func() error {
			close(firstEntered)
			<-releaseFirst
			return nil
		})
		if err != nil {
			firstResult <- -1
			return
		}
		firstResult <- previous
	}()
	<-firstEntered
	go func() {
		previous, err := handover.Commit(2, func() error {
			close(secondEntered)
			return nil
		})
		if err != nil {
			secondResult <- -1
			return
		}
		secondResult <- previous
	}()

	select {
	case <-secondEntered:
		t.Fatal("second publication overlapped first publication")
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseFirst)
	if previous := <-firstResult; previous != 0 {
		t.Fatalf("first previous=%d", previous)
	}
	if previous := <-secondResult; previous != 1 {
		t.Fatalf("second previous=%d", previous)
	}
	if current := handover.Current(); current != 2 {
		t.Fatalf("current=%d", current)
	}
	if handover.Clear(1) {
		t.Fatal("stale generation cleared replacement")
	}
	if !handover.Clear(2) || handover.Current() != 0 {
		t.Fatal("active generation was not cleared")
	}
}

func TestGenerationHandoverDoesNotActivateFailedPublication(t *testing.T) {
	var handover generationHandover[int]
	if _, err := handover.Commit(1, nil); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("publish failed")
	previous, err := handover.Commit(2, func() error { return failure })
	if !errors.Is(err, failure) || previous != 0 {
		t.Fatalf("previous=%d err=%v", previous, err)
	}
	if current := handover.Current(); current != 1 {
		t.Fatalf("failed publication changed active generation to %d", current)
	}
}
