package sessionproxy

import "testing"

func TestSequenceWindowAllowsBoundedReordering(t *testing.T) {
	var window sequenceWindow
	for _, sequence := range []uint64{10, 12, 11, 75, 74, 13} {
		if !window.Accept(sequence) { t.Fatalf("sequence %d rejected", sequence) }
	}
	for _, sequence := range []uint64{0, 75, 74, 10} {
		if window.Accept(sequence) { t.Fatalf("sequence %d replay/old value accepted", sequence) }
	}
}

func TestSequenceWindowAdvancesPastHistory(t *testing.T) {
	var window sequenceWindow
	if !window.Accept(1) || !window.Accept(65) { t.Fatal("failed to advance window") }
	if window.Accept(1) { t.Fatal("sequence outside 64-packet window accepted") }
	if !window.Accept(64) { t.Fatal("in-window reordered packet rejected") }
}
