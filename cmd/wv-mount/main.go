// wv-mount mounts the weaverssh vfs:// namespace as a real filesystem via
// macFUSE (macOS) or libfuse (Linux). It is equivalent to `wtool mount`.
package main

import (
	"os"

	"weaverssh/internal/vfscli"
)

func main() {
	args := append([]string{"mount"}, os.Args[1:]...)
	os.Exit(vfscli.Main("wtool", args))
}
