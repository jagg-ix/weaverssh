package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"weaverssh/sshagent"
)

func cmdSSHAgent(args []string) int {
	if len(args) == 0 {
		args = []string{"status"}
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "status":
		return cmdSSHAgentStatus(rest, os.Stdout, os.Stderr)
	case "list":
		return cmdSSHAgentList(rest, os.Stdout, os.Stderr)
	case "test":
		return cmdSSHAgentTest(rest, os.Stdout, os.Stderr)
	case "add":
		return cmdSSHAgentAdd(rest, os.Stdout, os.Stderr)
	case "remove", "delete":
		return cmdSSHAgentRemove(rest, os.Stdout, os.Stderr)
	case "help", "-h", "--help":
		printSSHAgentUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "wv ssh-agent: unknown command %q\n", verb)
		printSSHAgentUsage(os.Stderr)
		return 2
	}
}

func newSSHAgentFlagSet(name string, stderr io.Writer) (*flag.FlagSet, *string, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	binary := fs.String("ssh-add", envOrDefault("WEAVERSSH_SSH_ADD", "ssh-add"), "ssh-add executable")
	socket := fs.String("socket", os.Getenv("SSH_AUTH_SOCK"), "SSH agent socket; defaults to SSH_AUTH_SOCK")
	return fs, binary, socket
}

func cmdSSHAgentStatus(args []string, stdout, stderr io.Writer) int {
	fs, binary, socket := newSSHAgentFlagSet("ssh-agent status", stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	client := sshagent.Client{Binary: *binary, AuthSock: *socket}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	identities, err := client.List(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "wv ssh-agent status: %v\n", err)
		return 1
	}
	status := struct {
		Socket        string `json:"socket"`
		Available     bool   `json:"available"`
		IdentityCount int    `json:"identity_count"`
	}{Socket: client.Socket(), Available: true, IdentityCount: len(identities)}
	if *jsonOut {
		if err := json.NewEncoder(stdout).Encode(status); err != nil {
			fmt.Fprintf(stderr, "wv ssh-agent status: %v\n", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "ssh-agent: available\nsocket: %s\nidentities: %d\n", status.Socket, status.IdentityCount)
	return 0
}

func cmdSSHAgentList(args []string, stdout, stderr io.Writer) int {
	fs, binary, socket := newSSHAgentFlagSet("ssh-agent list", stderr)
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return 2
	}
	client := sshagent.Client{Binary: *binary, AuthSock: *socket}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	identities, err := client.List(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "wv ssh-agent list: %v\n", err)
		return 1
	}
	if *jsonOut {
		if err := json.NewEncoder(stdout).Encode(identities); err != nil {
			fmt.Fprintf(stderr, "wv ssh-agent list: %v\n", err)
			return 1
		}
		return 0
	}
	for _, identity := range identities {
		if identity.Comment == "" {
			fmt.Fprintf(stdout, "%s %s\n", identity.Fingerprint, identity.KeyType)
		} else {
			fmt.Fprintf(stdout, "%s %s %s\n", identity.Fingerprint, identity.KeyType, identity.Comment)
		}
	}
	return 0
}

func cmdSSHAgentTest(args []string, stdout, stderr io.Writer) int {
	fs, binary, socket := newSSHAgentFlagSet("ssh-agent test", stderr)
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wv ssh-agent test [--ssh-add PATH] [--socket PATH] PUBLIC_KEY")
		return 2
	}
	keyFile := fs.Arg(0)
	client := sshagent.Client{Binary: *binary, AuthSock: *socket}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	identity, err := client.EnsureLoaded(ctx, keyFile)
	if err != nil {
		fmt.Fprintf(stderr, "wv ssh-agent test: %v\n", err)
		return 1
	}
	if err := client.Test(ctx, keyFile); err != nil {
		fmt.Fprintf(stderr, "wv ssh-agent test: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "usable: %s %s\n", identity.Fingerprint, identity.KeyType)
	return 0
}

func cmdSSHAgentAdd(args []string, stdout, stderr io.Writer) int {
	fs, binary, socket := newSSHAgentFlagSet("ssh-agent add", stderr)
	lifetime := fs.String("lifetime", "", "maximum identity lifetime accepted by ssh-add -t")
	confirm := fs.Bool("confirm", false, "require confirmation before each key use (ssh-add -c)")
	quiet := fs.Bool("quiet", false, "suppress ssh-add success output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wv ssh-agent add [--lifetime 10m] [--confirm] PRIVATE_KEY")
		return 2
	}
	client := sshagent.Client{Binary: *binary, AuthSock: *socket}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := client.Add(ctx, fs.Arg(0), sshagent.AddOptions{Lifetime: *lifetime, Confirm: *confirm, Quiet: *quiet}); err != nil {
		fmt.Fprintf(stderr, "wv ssh-agent add: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "identity added")
	return 0
}

func cmdSSHAgentRemove(args []string, stdout, stderr io.Writer) int {
	fs, binary, socket := newSSHAgentFlagSet("ssh-agent remove", stderr)
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: wv ssh-agent remove PUBLIC_KEY")
		return 2
	}
	client := sshagent.Client{Binary: *binary, AuthSock: *socket}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := client.Remove(ctx, fs.Arg(0)); err != nil {
		fmt.Fprintf(stderr, "wv ssh-agent remove: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "identity removed")
	return 0
}

func printSSHAgentUsage(writer io.Writer) {
	fmt.Fprint(writer, `usage: wv ssh-agent <command> [options]

Commands:
  status                Verify agent connectivity and show key count
  list                  List loaded identities and SHA-256 fingerprints
  test PUBLIC_KEY       Verify the exact identity is loaded and usable
  add PRIVATE_KEY       Delegate identity loading to ssh-add
  remove PUBLIC_KEY     Remove the selected identity through ssh-add -d

Examples:
  wv ssh-agent status
  wv ssh-agent list --json
  wv ssh-agent test ~/.ssh/wv-hop.pub
  wv ssh-agent add --lifetime 10m --confirm ~/.ssh/wv-hop
  wv ssh-agent remove ~/.ssh/wv-hop.pub
`)
}

func envOrDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
