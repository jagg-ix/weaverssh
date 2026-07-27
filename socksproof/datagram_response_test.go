package socksproof

import (
	"testing"
	"time"

	"weaverssh/socksudp"
)

func TestDatagramResponseAuthenticationAndReplayWindow(t *testing.T) {
	now := time.Unix(1785000000, 0)
	challenge, err := NewChallenge(
		"proxy-a",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"binding-a",
		"node-a",
		30*time.Second,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	session, key, err := NewDatagramSession(challenge, now)
	if err != nil {
		t.Fatal(err)
	}
	decodedKey, err := session.ResponseKey(challenge, now)
	if err != nil {
		t.Fatal(err)
	}
	if string(decodedKey) != string(key) {
		t.Fatal("decoded response key does not match generated key")
	}
	packet, err := socksudp.Marshal("127.0.0.1:5353", []byte("response"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := EncodeDatagramResponse(key, challenge, 7, packet, now)
	if err != nil {
		t.Fatal(err)
	}
	response, decodedPacket, err := DecodeDatagramResponse(envelope, key, challenge, now)
	if err != nil {
		t.Fatal(err)
	}
	if response.Statement.Sequence != 7 || string(decodedPacket) != string(packet) {
		t.Fatalf("decoded response mismatch: sequence=%d packet=%q", response.Statement.Sequence, decodedPacket)
	}
	var window SequenceWindow
	if !window.Accept(7) {
		t.Fatal("first sequence was rejected")
	}
	if window.Accept(7) {
		t.Fatal("replayed sequence was accepted")
	}
	if !window.Accept(9) || !window.Accept(8) {
		t.Fatal("valid out-of-order sequence inside window was rejected")
	}
}

func TestDatagramResponseRejectsTampering(t *testing.T) {
	now := time.Unix(1785000100, 0)
	challenge, err := NewChallenge(
		"proxy-b",
		"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"binding-b",
		"node-b",
		30*time.Second,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := NewDatagramSession(challenge, now)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := socksudp.Marshal("127.0.0.1:53", []byte("dns"))
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := EncodeDatagramResponse(key, challenge, 1, packet, now)
	if err != nil {
		t.Fatal(err)
	}
	tamperedPayload := append([]byte(nil), envelope...)
	tamperedPayload[len(tamperedPayload)-1] ^= 0x01
	if _, _, err := DecodeDatagramResponse(tamperedPayload, key, challenge, now); err == nil {
		t.Fatal("tampered payload was accepted")
	}
	wrongKey := append([]byte(nil), key...)
	wrongKey[0] ^= 0xff
	if _, _, err := DecodeDatagramResponse(envelope, wrongKey, challenge, now); err == nil {
		t.Fatal("wrong response key was accepted")
	}
}
