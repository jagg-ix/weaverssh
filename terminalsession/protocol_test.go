package terminalsession

import (
	"bytes"
	"strings"
	"testing"
)

func TestCodecRoundTripAndBounds(t *testing.T) {
	codec := Codec{MaxPayload: 32}
	want := Frame{Type: FrameOutput, Flags: FlagReplay, Sequence: 9, Payload: []byte("hello")}
	var wire bytes.Buffer
	if err := codec.WriteFrame(&wire, want); err != nil {
		t.Fatal(err)
	}
	got, err := codec.ReadFrame(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != want.Type || got.Flags != want.Flags || got.Sequence != want.Sequence || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("frame mismatch: got=%+v want=%+v", got, want)
	}
	if err := codec.WriteFrame(&bytes.Buffer{}, Frame{Type: FrameInput, Payload: []byte(strings.Repeat("x", 33))}); err == nil {
		t.Fatal("oversized input frame was accepted")
	}
	if err := codec.WriteFrame(&bytes.Buffer{}, Frame{Type: FrameResize, Payload: []byte{1, 2}}); err == nil {
		t.Fatal("invalid resize shape was accepted")
	}
	if err := codec.WriteFrame(&bytes.Buffer{}, Frame{Type: FrameInput, Sequence: 1}); err == nil {
		t.Fatal("sequence on non-output frame was accepted")
	}
	if err := codec.WriteFrame(&bytes.Buffer{}, Frame{Type: FrameOutput, Flags: FlagTruncated, Sequence: 1, Payload: []byte("tail")}); err == nil {
		t.Fatal("live output claimed replay truncation")
	}
}

func TestReplayRingReportsTruncation(t *testing.T) {
	ring := newReplayRing(5)
	ring.append(Frame{Type: FrameOutput, Sequence: 1, Payload: []byte("abc")})
	ring.append(Frame{Type: FrameOutput, Sequence: 2, Payload: []byte("def")})
	frames := ring.after(0)
	if len(frames) != 1 || frames[0].Sequence != 2 || frames[0].Flags&FlagReplay == 0 || frames[0].Flags&FlagTruncated == 0 {
		t.Fatalf("unexpected truncated replay: %+v", frames)
	}
	if ring.dropped != 3 {
		t.Fatalf("dropped=%d want=3", ring.dropped)
	}
}
