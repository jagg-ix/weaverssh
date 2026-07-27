//go:build !linux && !darwin

package main

import (
	"fmt"
	"os"
)

func mountArgumentError(err error) int { fmt.Fprintf(os.Stderr, "wv mount: %v\n", err); return 2 }
func cmdSessionMount(args []string) int {
	fmt.Fprintln(os.Stderr, "wv mount NODE:/ is supported on Linux and macOS with FUSE")
	return 1
}
