//go:build !linux && !darwin

// Package vfsmount has no FUSE implementation on this platform; mounting is
// offered only on Linux (libfuse) and macOS (macFUSE). This file keeps the
// package non-empty so `go build ./...` succeeds everywhere.
package vfsmount
