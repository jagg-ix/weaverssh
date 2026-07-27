package sshunit

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBuildSSHArgsAndHostKeyPolicies(t *testing.T) {
	args, err := BuildSSHArgs("root", "203.0.113.20", 22, "~/.ssh/id_ed25519", HostKeyAcceptNew, true, "echo ok")
	if err != nil {
		t.Fatalf("BuildSSHArgs unexpected err: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=accept-new") {
		t.Fatalf("missing accept-new policy: %v", args)
	}
	if !strings.Contains(joined, "-i ~/.ssh/id_ed25519") {
		t.Fatalf("missing identity file: %v", args)
	}
	if !strings.Contains(joined, "-X -o ForwardX11=yes") {
		t.Fatalf("missing x11 opts: %v", args)
	}

	_, err = BuildSSHArgs("", "host", 22, "", HostKeyStrict, false, "echo ok")
	if err == nil || err.Error() != "missing_user" {
		t.Fatalf("expected missing_user, got %v", err)
	}
	_, err = BuildSSHArgs("root", "host", 70000, "", HostKeyStrict, false, "echo ok")
	if err == nil || err.Error() != "invalid_port" {
		t.Fatalf("expected invalid_port, got %v", err)
	}
}

func TestParseEndpointBoundaries(t *testing.T) {
	type tc struct {
		raw      string
		def      int
		wantHost string
		wantPort int
		wantErr  string
	}
	cases := []tc{
		{raw: "203.0.113.20", def: 22, wantHost: "203.0.113.20", wantPort: 22},
		{raw: "203.0.113.20:2222", def: 22, wantHost: "203.0.113.20", wantPort: 2222},
		{raw: "[2001:db8::1]:22", def: 22, wantHost: "2001:db8::1", wantPort: 22},
		{raw: "", def: 22, wantErr: "missing_endpoint"},
		{raw: "host:", def: 22, wantErr: "invalid_endpoint"},
		{raw: "ssh://host:22", def: 22, wantErr: "scheme_not_supported"},
	}
	for _, c := range cases {
		h, p, err := ParseEndpoint(c.raw, c.def)
		if c.wantErr != "" {
			if err == nil || err.Error() != c.wantErr {
				t.Fatalf("ParseEndpoint(%q) err=%v want=%q", c.raw, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseEndpoint(%q) unexpected err: %v", c.raw, err)
		}
		if h != c.wantHost || p != c.wantPort {
			t.Fatalf("ParseEndpoint(%q)=(%q,%d) want=(%q,%d)", c.raw, h, p, c.wantHost, c.wantPort)
		}
	}
}

func TestVerifyHostKeyFingerprint(t *testing.T) {
	if err := VerifyHostKeyFingerprint("SHA256:abc", "SHA256:abc"); err != nil {
		t.Fatalf("expected match, got err %v", err)
	}
	if err := VerifyHostKeyFingerprint("SHA256:abc", "SHA256:def"); err == nil || err.Error() != "hostkey_mismatch" {
		t.Fatalf("expected hostkey_mismatch, got %v", err)
	}
}

func TestChannelLifecycleAndTransportDouble(t *testing.T) {
	tx := &FakeTransport{}
	ch := NewChannel(tx)
	if ch.State() != ChannelNew {
		t.Fatalf("unexpected initial state: %s", ch.State())
	}
	if err := ch.Send([]byte("hi")); err == nil || err.Error() != "channel_not_open" {
		t.Fatalf("expected channel_not_open, got %v", err)
	}
	if err := ch.Open(); err != nil {
		t.Fatalf("open failed: %v", err)
	}
	if err := ch.Send([]byte("payload")); err != nil {
		t.Fatalf("send failed: %v", err)
	}
	if err := ch.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}
	if ch.State() != ChannelClosed {
		t.Fatalf("unexpected final state: %s", ch.State())
	}
	if tx.OpenCalls != 1 || tx.WriteCalls != 1 || tx.CloseCalls != 1 {
		t.Fatalf("unexpected call counts: %+v", tx)
	}
	if len(tx.Payloads) != 1 || !reflect.DeepEqual(tx.Payloads[0], []byte("payload")) {
		t.Fatalf("payload capture mismatch: %+v", tx.Payloads)
	}
}

func TestChannelRetryTimeoutThenSuccess(t *testing.T) {
	tx := &FakeTransport{
		OpenErrors: []error{
			errors.New("timeout"),
			nil,
		},
	}
	ch := NewChannel(tx)
	if err := ch.OpenWithRetry(2, 0); err != nil {
		t.Fatalf("expected retry success, got %v", err)
	}
	if tx.OpenCalls != 2 {
		t.Fatalf("expected 2 open calls, got %d", tx.OpenCalls)
	}
}

func TestChannelConcurrentSendCloseRaceProfile(t *testing.T) {
	tx := &FakeTransport{}
	ch := NewChannel(tx)
	if err := ch.Open(); err != nil {
		t.Fatalf("open failed: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = ch.Send([]byte("x"))
			time.Sleep(time.Microsecond)
			_ = ch.Close()
		}()
	}
	wg.Wait()
	if ch.State() != ChannelClosed {
		t.Fatalf("expected closed state, got %s", ch.State())
	}
}

func FuzzParseEndpoint(f *testing.F) {
	seeds := []string{
		"203.0.113.20",
		"203.0.113.20:22",
		"[2001:db8::1]:22",
		"host:",
		"",
		"ssh://host:22",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		host, port, err := ParseEndpoint(raw, 22)
		if err != nil {
			if err.Error() == "" {
				t.Fatalf("error must include message")
			}
			return
		}
		if strings.TrimSpace(host) == "" {
			t.Fatalf("host must not be empty when err=nil")
		}
		if port <= 0 || port > 65535 {
			t.Fatalf("port out of range: %d", port)
		}
	})
}
