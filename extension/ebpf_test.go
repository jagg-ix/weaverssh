package extension

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

type testEBPFRuntime struct {
	decision uint32
	err      error
	program  string
	input    []byte
}

func (r *testEBPFRuntime) Name() string { return "test-vm" }

func (r *testEBPFRuntime) Run(_ context.Context, request EBPFRuntimeRequest) (uint32, error) {
	r.program = request.Program
	r.input = append([]byte(nil), request.Input...)
	return r.decision, r.err
}

func TestMarshalEBPFEventUsesFixedPrivacyPreservingABI(t *testing.T) {
	event := NewEvent(PointTargetAuthorized)
	event.OccurredAtUnixNano = 123456789
	event.SessionBinding = "binding-secret"
	event.LocalNode = "workstation-42"
	event.PeerNode = "jump-a"
	event.TargetNode = "compute-node"
	event.Service = "tcp"
	event.ServiceID = 3
	event.MetadataBytes = 123
	metadata := sha256.Sum256([]byte("private-metadata"))
	event.MetadataSHA256 = formatSHA256(metadata)
	event.Attributes = map[string]string{"role": "host", "dispatch": "local"}

	payload, err := MarshalEBPFEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) != EBPFEventSize {
		t.Fatalf("size=%d want=%d", len(payload), EBPFEventSize)
	}
	if string(payload[:4]) != "WVEB" || binary.LittleEndian.Uint16(payload[4:6]) != 1 {
		t.Fatalf("invalid ABI header %x", payload[:8])
	}
	if point := binary.LittleEndian.Uint16(payload[6:8]); point != 4 {
		t.Fatalf("point=%d", point)
	}
	if service := binary.LittleEndian.Uint16(payload[8:10]); service != 3 {
		t.Fatalf("service=%d", service)
	}
	if bytes.Contains(payload, []byte("binding-secret")) || bytes.Contains(payload, []byte("compute-node")) || bytes.Contains(payload, []byte("private-metadata")) {
		t.Fatal("raw private event data crossed the eBPF ABI")
	}
	if !bytes.Equal(payload[ebpfOffsetMetadataDigest:ebpfOffsetMetadataDigest+32], metadata[:]) {
		t.Fatal("metadata digest was not preserved")
	}

	reordered := event
	reordered.Attributes = map[string]string{"dispatch": "local", "role": "host"}
	second, err := MarshalEBPFEvent(reordered)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, second) {
		t.Fatal("attribute map order changed the ABI")
	}
}

func TestEBPFHookAllowAndDeny(t *testing.T) {
	runtime := &testEBPFRuntime{}
	hook, err := NewEBPFHook(runtime, EBPFHookConfig{
		Point: PointTargetForwarding, Program: "policy/program", Runtime: "test-vm", Mode: ModeEnforce,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := hook.Handler(context.Background(), NewEvent(PointTargetForwarding)); err != nil {
		t.Fatalf("allow decision failed: %v", err)
	}
	if runtime.program != "policy/program" || len(runtime.input) != EBPFEventSize {
		t.Fatalf("program=%q input=%d", runtime.program, len(runtime.input))
	}
	runtime.decision = 7
	if err := hook.Handler(context.Background(), NewEvent(PointTargetForwarding)); err == nil {
		t.Fatal("expected nonzero eBPF decision to reject")
	}
	runtime.decision = 0
	runtime.err = errors.New("vm failure")
	if err := hook.Handler(context.Background(), NewEvent(PointTargetForwarding)); err == nil {
		t.Fatal("expected runtime failure")
	}
}

func TestRegisterEBPFMarksRuntime(t *testing.T) {
	runtime := &testEBPFRuntime{}
	hook, err := NewEBPFHook(runtime, EBPFHookConfig{Point: PointSessionReady, Program: "policy/program"})
	if err != nil {
		t.Fatal(err)
	}
	registry := NewRegistry(nil)
	if err := registry.RegisterEBPF(Definition{
		Descriptor: Descriptor{Name: "ebpf-policy", Version: "1"},
		Hooks:      []Hook{hook},
	}); err != nil {
		t.Fatal(err)
	}
	if !registry.HasRuntime(EBPFRuntimeKind) {
		t.Fatal("eBPF runtime was not recorded")
	}
}

func TestEBPFHookRejectsRuntimeMismatch(t *testing.T) {
	_, err := NewEBPFHook(&testEBPFRuntime{}, EBPFHookConfig{
		Point: PointSessionReady, Program: "policy/program", Runtime: "other-vm",
	})
	if err == nil {
		t.Fatal("expected runtime mismatch rejection")
	}
}

func formatSHA256(value [sha256.Size]byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, sha256.Size*2)
	for index, b := range value {
		out[index*2] = alphabet[b>>4]
		out[index*2+1] = alphabet[b&0x0f]
	}
	return string(out)
}
