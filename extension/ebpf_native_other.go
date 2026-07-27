package extension

import "context"

func nativePinnedEBPFAvailable() bool { return false }

func validateNativePinnedEBPF(string) error { return ErrEBPFUnsupported }

func runNativePinnedEBPF(context.Context, string, []byte) (uint32, error) {
	return 0, ErrEBPFUnsupported
}
