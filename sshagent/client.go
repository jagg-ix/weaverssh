// Package sshagent provides a small, testable adapter around OpenSSH ssh-add.
// It never reads private-key bytes; ssh-add and ssh-agent retain responsibility
// for passphrases, hardware-backed keys, confirmation, and key lifetimes.
package sshagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var (
	ErrUnavailable       = errors.New("sshagent: authentication agent is unavailable")
	ErrIdentityNotLoaded = errors.New("sshagent: identity is not loaded")
)

type Identity struct {
	KeyType     string `json:"key_type"`
	KeyBlob     string `json:"key_blob"`
	Comment     string `json:"comment,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

func (i Identity) Canonical() string {
	return strings.TrimSpace(i.KeyType) + " " + strings.TrimSpace(i.KeyBlob)
}

type AddOptions struct {
	Lifetime string
	Confirm  bool
	Quiet    bool
}

type RunFunc func(ctx context.Context, binary string, args []string, environment []string) (stdout, stderr []byte, err error)

type Client struct {
	Binary   string
	AuthSock string
	Run      RunFunc
}

func (c Client) Socket() string {
	if value := strings.TrimSpace(c.AuthSock); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
}

func (c Client) List(ctx context.Context) ([]Identity, error) {
	if c.Socket() == "" {
		return nil, fmt.Errorf("%w: SSH_AUTH_SOCK is empty", ErrUnavailable)
	}
	stdout, stderr, err := c.run(ctx, []string{"-L"})
	combined := strings.TrimSpace(string(append(append([]byte(nil), stdout...), stderr...)))
	if isNoIdentitiesMessage(combined) {
		return []Identity{}, nil
	}
	if err != nil {
		return nil, classifyRunError("list identities", err, combined)
	}
	var identities []Identity
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		identity, parseErr := ParsePublicKey(line)
		if parseErr != nil {
			return nil, fmt.Errorf("sshagent: parse ssh-add -L output: %w", parseErr)
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

func (c Client) EnsureLoaded(ctx context.Context, publicKeyFile string) (Identity, error) {
	expected, err := LoadPublicKeyFile(publicKeyFile)
	if err != nil {
		return Identity{}, err
	}
	identities, err := c.List(ctx)
	if err != nil {
		return Identity{}, err
	}
	for _, identity := range identities {
		if identity.Canonical() == expected.Canonical() {
			return identity, nil
		}
	}
	return Identity{}, fmt.Errorf("%w: %s (%s); run `wv ssh-agent add PRIVATE_KEY` or set WEAVERSSH_HOP_AGENT_ADD", ErrIdentityNotLoaded, expected.Fingerprint, publicKeyFile)
}

func (c Client) Test(ctx context.Context, publicKeyFile string) error {
	if _, err := LoadPublicKeyFile(publicKeyFile); err != nil {
		return err
	}
	if c.Socket() == "" {
		return fmt.Errorf("%w: SSH_AUTH_SOCK is empty", ErrUnavailable)
	}
	_, stderr, err := c.run(ctx, []string{"-T", publicKeyFile})
	if err != nil {
		message := strings.TrimSpace(string(stderr))
		if isAgentUnavailableMessage(message) {
			return fmt.Errorf("%w: %s", ErrUnavailable, message)
		}
		return fmt.Errorf("sshagent: ssh-add -T failed: %w: %s", err, message)
	}
	return nil
}

func (c Client) Add(ctx context.Context, privateKeyFile string, options AddOptions) error {
	privateKeyFile = strings.TrimSpace(privateKeyFile)
	if privateKeyFile == "" {
		return errors.New("sshagent: private key file is required")
	}
	if c.Socket() == "" {
		return fmt.Errorf("%w: SSH_AUTH_SOCK is empty", ErrUnavailable)
	}
	args := []string{}
	if options.Quiet {
		args = append(args, "-q")
	}
	if options.Confirm {
		args = append(args, "-c")
	}
	if lifetime := strings.TrimSpace(options.Lifetime); lifetime != "" {
		if strings.ContainsAny(lifetime, "\x00\r\n") {
			return errors.New("sshagent: invalid identity lifetime")
		}
		args = append(args, "-t", lifetime)
	}
	args = append(args, privateKeyFile)
	_, stderr, err := c.run(ctx, args)
	if err != nil {
		return classifyRunError("add identity", err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

func (c Client) Remove(ctx context.Context, publicKeyFile string) error {
	if _, err := LoadPublicKeyFile(publicKeyFile); err != nil {
		return err
	}
	if c.Socket() == "" {
		return fmt.Errorf("%w: SSH_AUTH_SOCK is empty", ErrUnavailable)
	}
	_, stderr, err := c.run(ctx, []string{"-d", publicKeyFile})
	if err != nil {
		return classifyRunError("remove identity", err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

func (c Client) run(ctx context.Context, args []string) ([]byte, []byte, error) {
	binary := strings.TrimSpace(c.Binary)
	if binary == "" {
		binary = "ssh-add"
	}
	run := c.Run
	if run == nil {
		run = execRun
	}
	return run(ctx, binary, args, environmentWithAuthSock(c.Socket()))
}

func execRun(ctx context.Context, binary string, args []string, environment []string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = environment
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return stdout.Bytes(), stderr.Bytes(), err
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

func environmentWithAuthSock(socket string) []string {
	environment := os.Environ()
	if strings.TrimSpace(socket) == "" {
		return environment
	}
	out := make([]string, 0, len(environment)+1)
	for _, entry := range environment {
		if strings.HasPrefix(entry, "SSH_AUTH_SOCK=") {
			continue
		}
		out = append(out, entry)
	}
	return append(out, "SSH_AUTH_SOCK="+socket)
}

func classifyRunError(operation string, runErr error, message string) error {
	if isAgentUnavailableMessage(message) {
		return fmt.Errorf("%w: %s", ErrUnavailable, message)
	}
	if message == "" {
		return fmt.Errorf("sshagent: %s: %w", operation, runErr)
	}
	return fmt.Errorf("sshagent: %s: %w: %s", operation, runErr, message)
}

func isNoIdentitiesMessage(message string) bool {
	message = strings.ToLower(message)
	return strings.Contains(message, "agent has no identities") || strings.Contains(message, "no identities")
}

func isAgentUnavailableMessage(message string) bool {
	message = strings.ToLower(message)
	return strings.Contains(message, "could not open a connection to your authentication agent") ||
		strings.Contains(message, "error connecting to agent") ||
		strings.Contains(message, "communication with agent failed") ||
		strings.Contains(message, "no such file or directory")
}

func ParsePublicKey(line string) (Identity, error) {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 {
		return Identity{}, errors.New("invalid OpenSSH public key")
	}
	keyIndex := -1
	for index := 0; index+1 < len(fields); index++ {
		if looksLikeKeyType(fields[index]) {
			keyIndex = index
			break
		}
	}
	if keyIndex < 0 {
		return Identity{}, errors.New("OpenSSH key type not found")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[keyIndex+1])
	if err != nil || len(blob) == 0 {
		return Identity{}, errors.New("invalid OpenSSH key blob")
	}
	comment := ""
	if keyIndex+2 < len(fields) {
		comment = strings.Join(fields[keyIndex+2:], " ")
	}
	digest := sha256.Sum256(blob)
	return Identity{
		KeyType:     fields[keyIndex],
		KeyBlob:     fields[keyIndex+1],
		Comment:     comment,
		Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:]),
	}, nil
}

func LoadPublicKeyFile(path string) (Identity, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Identity{}, errors.New("sshagent: public key file is required")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return Identity{}, fmt.Errorf("sshagent: read public key %s: %w", path, err)
	}
	if bytes.Contains(payload, []byte("PRIVATE KEY-----")) {
		return Identity{}, fmt.Errorf("sshagent: %s is a private key; use its .pub file for identity selection", path)
	}
	for _, line := range strings.Split(string(payload), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		identity, parseErr := ParsePublicKey(line)
		if parseErr == nil {
			return identity, nil
		}
	}
	return Identity{}, fmt.Errorf("sshagent: no OpenSSH public key found in %s", path)
}

func looksLikeKeyType(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return strings.HasPrefix(value, "ssh-") ||
		strings.HasPrefix(value, "ecdsa-") ||
		strings.HasPrefix(value, "sk-") ||
		strings.Contains(value, "@openssh.com")
}
