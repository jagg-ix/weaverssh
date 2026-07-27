//go:build linux || darwin

package vfscli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"weaverssh/internal/vfs"
	"weaverssh/internal/vfsmount"
)

// runMount connects to the resolved 9P endpoint and mounts the vfs:// namespace
// at opts.mountpoint, blocking until the filesystem is unmounted.
func runMount(opts mountOptions) error {
	if err := preflightFUSE(); err != nil {
		return err
	}
	if err := os.MkdirAll(opts.mountpoint, 0o755); err != nil {
		return fmt.Errorf("mountpoint %s: %w", opts.mountpoint, err)
	}
	view, err := activeView()
	if err != nil {
		return err
	}
	c, err := vfs.Connect(dialTimeout)
	if err != nil {
		return err
	}
	defer c.Close()

	server, err := vfsmount.Mount(opts.mountpoint, c, vfsmount.Options{
		ReadOnly:   !opts.readWrite,
		AllowOther: opts.allowOther,
		VolumeName: opts.volumeName,
		Debug:      opts.debug,
		View:       view,
	})
	if err != nil {
		return fmt.Errorf("mount %s: %w", opts.mountpoint, err)
	}

	endpoint, socks := vfs.Endpoint()
	mode := "read-only"
	if opts.readWrite {
		mode = "read-write"
	}
	via := endpoint
	if socks != "" {
		via += " via socks " + socks
	}
	fmt.Printf("mounted vfs:// (%s) at %s  [endpoint %s]\n", mode, opts.mountpoint, via)
	fmt.Printf("unmount with: wtool unmount %s   (or Ctrl-C)\n", opts.mountpoint)

	// Unmount cleanly on SIGINT/SIGTERM so the mountpoint is not left stale.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		_ = server.Unmount()
	}()
	server.Wait()
	return nil
}

// preflightFUSE checks that FUSE is usable before mounting and turns common
// WSL1, package-missing, and helper-missing failures into actionable messages.
func preflightFUSE() error {
	return currentFUSEStatus().PreflightError()
}

// runUnmount detaches a mount started elsewhere, trying the FUSE helper first
// then the generic umount(8).
func runUnmount(mountpoint string) error {
	var errs []error
	for _, c := range [][]string{
		{"fusermount", "-u", mountpoint}, // libfuse (Linux)
		{"fusermount3", "-u", mountpoint},
		{"umount", mountpoint},              // macOS / Linux fallback
		{"diskutil", "unmount", mountpoint}, // macOS fallback
	} {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err == nil {
			fmt.Printf("unmounted %s\n", mountpoint)
			return nil
		} else {
			errs = append(errs, fmt.Errorf("%s: %v: %s", c[0], err, out))
		}
	}
	if len(errs) == 0 {
		return fmt.Errorf("no unmount helper found (need fusermount or umount)")
	}
	return fmt.Errorf("unmount failed: %v", errs)
}
