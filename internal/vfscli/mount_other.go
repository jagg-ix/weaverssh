//go:build !linux && !darwin

package vfscli

import "weaverssh/wverrors"

// FUSE mounting requires macFUSE (macOS) or libfuse/kernel-FUSE (Linux); it is
// unavailable on this platform. wcp/wls/wmkdir and the vfs:// CLI still work.
func runMount(_ mountOptions) error {
	return wverrors.New(wverrors.CodeFuseUnavailable, "vfs", "mount", "FUSE mounting is only supported on Linux (libfuse) and macOS (macFUSE); use wcp/wls/wmkdir here")
}

func runUnmount(_ string) error {
	return wverrors.New(wverrors.CodeFuseUnavailable, "vfs", "unmount", "FUSE mounting is only supported on Linux and macOS")
}
