package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"

	"weaverssh/authproof"
)

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	privatePath := fs.String("private", "weaverssh.key", "private key output path")
	publicPath := fs.String("public", "weaverssh.key.pub", "public key output path")
	force := fs.Bool("force", false, "replace existing output files")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv keygen [--private FILE] [--public FILE] [--force]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	for _, path := range []string{*privatePath, *publicPath} {
		if strings.TrimSpace(path) == "" {
			fmt.Fprintln(os.Stderr, "keygen: output path cannot be empty")
			return 2
		}
		if !*force {
			if _, err := os.Stat(path); err == nil {
				fmt.Fprintf(os.Stderr, "keygen: %s already exists; use --force to replace it\n", path)
				return 1
			} else if !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "keygen: stat %s: %v\n", path, err)
				return 1
			}
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen: %v\n", err)
		return 1
	}
	privateData := []byte(authproof.EncodePrivateKey(privateKey) + "\n")
	publicData := []byte(authproof.EncodePublicKey(publicKey) + "\n")
	if err := os.WriteFile(*privatePath, privateData, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "keygen: write private key: %v\n", err)
		return 1
	}
	if err := os.WriteFile(*publicPath, publicData, 0o644); err != nil {
		_ = os.Remove(*privatePath)
		fmt.Fprintf(os.Stderr, "keygen: write public key: %v\n", err)
		return 1
	}
	fmt.Printf("private: %s\npublic:  %s\n", *privatePath, *publicPath)
	return 0
}
