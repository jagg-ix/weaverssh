package main

import (
	"os"

	"weaverssh/internal/vfscli"
)

func main() {
	os.Exit(vfscli.Main(os.Args[0], os.Args[1:]))
}
