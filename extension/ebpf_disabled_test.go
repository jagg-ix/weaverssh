//go:build !ebpf

package extension

import (
	"errors"
	"testing"
)

func TestNativePinnedEBPFRequiresBuildTag(t *testing.T) {
	if NativePinnedEBPFAvailable() {
		t.Fatal("native pinned eBPF provider is active without the ebpf build tag")
	}
	_, err := configuredEBPFHook(EBPFHookConfig{
		Point: PointSessionReady, Runtime: EBPFRuntimePinned, Program: "unused-pin",
	})
	if !errors.Is(err, ErrEBPFUnsupported) {
		t.Fatalf("error=%v want ErrEBPFUnsupported", err)
	}
}
