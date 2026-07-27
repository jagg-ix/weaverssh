package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"weaverssh/authproof"
	"weaverssh/socksproof"
)

func cmdSocksPolicy(args []string) int {
	if len(args) == 0 {
		printSocksPolicyUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return cmdSocksPolicyValidate(args[1:])
	case "key-info":
		return cmdSocksPolicyKeyInfo(args[1:])
	case "help", "-h", "--help":
		printSocksPolicyUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "wv socks-policy: unknown command %q\n", args[0])
		printSocksPolicyUsage(os.Stderr)
		return 2
	}
}

func cmdSocksPolicyValidate(args []string) int {
	fs := flag.NewFlagSet("socks-policy validate", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit JSON summary")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: wv socks-policy validate [--json] POLICY.json")
		return 2
	}
	policy, err := socksproof.LoadPolicyFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-policy validate: %v\n", err)
		return 1
	}
	verifier, err := socksproof.NewVerifier(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-policy validate: %v\n", err)
		return 1
	}
	normalized, err := socksproof.NormalizePolicy(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-policy validate: %v\n", err)
		return 1
	}
	type principalSummary struct {
		ID           string   `json:"id"`
		Fingerprint  string   `json:"fingerprint"`
		Capabilities []string `json:"capabilities"`
		Destinations []string `json:"destinations"`
		MaxTTL       string   `json:"max_ttl"`
	}
	summary := struct {
		Version      string             `json:"version"`
		ServerID     string             `json:"server_id"`
		PolicySHA256 string             `json:"policy_sha256"`
		Principals   []principalSummary `json:"principals"`
	}{Version: normalized.Version, ServerID: normalized.ServerID, PolicySHA256: verifier.PolicySHA256}
	for _, principal := range normalized.Principals {
		key, err := authproof.DecodePublicKey(principal.PublicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "wv socks-policy validate: principal %s: %v\n", principal.ID, err)
			return 1
		}
		summary.Principals = append(summary.Principals, principalSummary{
			ID:           principal.ID,
			Fingerprint:  openSSHEd25519Fingerprint(key),
			Capabilities: append([]string(nil), principal.Capabilities...),
			Destinations: append([]string(nil), principal.Destinations...),
			MaxTTL:       principal.MaxTTL,
		})
	}
	if *jsonOut {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(summary); err != nil {
			fmt.Fprintf(os.Stderr, "wv socks-policy validate: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Printf("valid SOCKS proof policy\nserver_id: %s\npolicy_sha256: %s\nprincipals: %d\n", summary.ServerID, summary.PolicySHA256, len(summary.Principals))
	for _, principal := range summary.Principals {
		fmt.Printf("- %s %s destinations=%d max_ttl=%s\n", principal.ID, principal.Fingerprint, len(principal.Destinations), displayDefault(principal.MaxTTL, "30s"))
	}
	return 0
}

func cmdSocksPolicyKeyInfo(args []string) int {
	fs := flag.NewFlagSet("socks-policy key-info", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: wv socks-policy key-info PUBLIC_KEY_FILE")
		return 2
	}
	payload, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-policy key-info: %v\n", err)
		return 1
	}
	key, err := authproof.DecodePublicKey(strings.TrimSpace(string(payload)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "wv socks-policy key-info: %v\n", err)
		return 1
	}
	fmt.Printf("fingerprint: %s\nalgorithm: Ed25519\nencoded_public_key: %s\n", openSSHEd25519Fingerprint(key), authproof.EncodePublicKey(key))
	return 0
}

func openSSHEd25519Fingerprint(key []byte) string {
	var blob bytes.Buffer
	writeSSHString := func(payload []byte) {
		_ = binary.Write(&blob, binary.BigEndian, uint32(len(payload)))
		_, _ = blob.Write(payload)
	}
	writeSSHString([]byte("ssh-ed25519"))
	writeSSHString(key)
	digest := sha256.Sum256(blob.Bytes())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
}

func displayDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func printSocksPolicyUsage(writer io.Writer) {
	fmt.Fprint(writer, `usage: wv socks-policy <command> [options]

Commands:
  validate POLICY.json       Validate policy and print its canonical SHA-256 digest
  key-info PUBLIC_KEY_FILE   Print the OpenSSH-compatible Ed25519 fingerprint
`)
}
