package sessionapi

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestMessageFramingRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	payload := []byte(`{"protocol":"weaverssh.session-api.v1"}`)
	if err := writeMessage(&buffer, payload); err != nil {
		t.Fatal(err)
	}
	got, err := readMessage(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got=%q want=%q", got, payload)
	}
}

func TestMessageFramingRejectsOversizedPayload(t *testing.T) {
	payload := bytes.Repeat([]byte{'x'}, MaxMessageBytes+1)
	payload = append(payload, '\n')
	if _, err := readMessage(bytes.NewReader(payload)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("error=%v want ErrMessageTooLarge", err)
	}
	if err := writeMessage(io.Discard, bytes.Repeat([]byte{'x'}, MaxMessageBytes+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("write error=%v want ErrMessageTooLarge", err)
	}
}

func TestMessageFramingRequiresTerminator(t *testing.T) {
	if _, err := readMessage(bytes.NewReader([]byte(`{"id":"request"}`))); err == nil {
		t.Fatal("unterminated message was accepted")
	}
}

func TestMessageFramingRejectsEmptyFrame(t *testing.T) {
	if _, err := readMessage(bytes.NewReader([]byte{'\n'})); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("error=%v want ErrMessageTooLarge", err)
	}
}
