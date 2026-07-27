//go:build linux || darwin

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"weaverssh/internal/vfsmount"
)

func mountArgumentError(err error) int { fmt.Fprintf(os.Stderr, "wv mount: %v\n", err); return 2 }

func cmdSessionMount(args []string) int {
	fs := flag.NewFlagSet("mount", flag.ContinueOnError)
	readWrite := fs.Bool("read-write", false, "allow filesystem mutations")
	allowOther := fs.Bool("allow-other", false, "allow users other than the mounter; requires user_allow_other")
	volumeName := fs.String("volume-name", "WeaverSSH", "macOS Finder volume label")
	debug := fs.Bool("debug", false, "enable FUSE protocol logging")
	cacheTTL := fs.Duration("cache-ttl", time.Second, "metadata cache lifetime; negative disables")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv mount [options] NODE:/ MOUNTPOINT")
		fmt.Fprintln(os.Stderr, "The first broker-aware mount targets the signed node export root; use NODE:/ exactly.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}
	ref, matched, err := parseSessionPath(fs.Arg(0))
	if err != nil || !matched {
		return mountArgumentError(firstError(err, fmt.Errorf("expected NODE:/")))
	}
	if ref.Path != "" {
		return mountArgumentError(fmt.Errorf("broker-aware FUSE currently mounts the signed export root; use %s:/", ref.Node))
	}
	mountpoint := strings.TrimSpace(fs.Arg(1))
	if mountpoint == "" {
		return mountArgumentError(fmt.Errorf("mountpoint is required"))
	}
	if err := os.MkdirAll(mountpoint, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "wv mount: create mountpoint: %v\n", err)
		return 1
	}
	client, err := activeSessionClient(context.Background(), ref.Node)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv mount: %v\n", err)
		return 1
	}
	defer client.Close()
	root, err := client.Stat("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv mount: inspect signed export root: %v\n", err)
		return 1
	}
	if !root.IsDir {
		fmt.Fprintln(os.Stderr, "wv mount: signed export root is not a directory")
		return 1
	}
	server, err := vfsmount.Mount(mountpoint, client, vfsmount.Options{ReadOnly: !*readWrite, AllowOther: *allowOther, VolumeName: *volumeName, Debug: *debug, CacheTTL: *cacheTTL})
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv mount: %v\n", err)
		return 1
	}
	mode := "read-only"
	if *readWrite {
		mode = "read-write"
	}
	fmt.Printf("mounted %s:/ at %s (%s, broker-routed ServiceFS)\n", ref.Node, mountpoint, mode)
	fmt.Printf("unmount with: wv unmount %s  (or Ctrl-C)\n", mountpoint)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() { <-sig; _ = server.Unmount() }()
	server.Wait()
	return 0
}
