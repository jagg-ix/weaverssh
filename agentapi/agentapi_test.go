package agentapi

import "testing"

func TestNewRuntimeRejectsMissingCookie(t *testing.T) {
	if _, err := NewRuntime(Config{X11Target: "127.0.0.1:9"}); err == nil {
		t.Fatal("missing auth cookie should fail")
	}
}

func TestNewRuntimeUsesLibraryInterface(t *testing.T) {
	t.Setenv("DISPLAY", "")
	runtime, err := NewRuntime(Config{AuthCookie: "00112233445566778899aabbccddeeff", X11Target: "127.0.0.1:9"})
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if runtime == nil || runtime.inner == nil {
		t.Fatal("runtime not initialized")
	}
	if got := runtime.inner.InterfaceMode(); got != "library" {
		t.Fatalf("interface mode=%q, want library", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
