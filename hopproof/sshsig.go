package hopproof

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// SSHKeygenSigner signs through ssh-keygen -Y sign. KeyFile may contain only the
// public key when its private half is available through the local or forwarded
// ssh-agent.
type SSHKeygenSigner struct {
	Binary  string
	KeyFile string
}

func (s SSHKeygenSigner) Sign(ctx context.Context, principal string, message []byte) ([]byte, error) {
	binary := strings.TrimSpace(s.Binary)
	if binary == "" {
		binary = "ssh-keygen"
	}
	keyFile := strings.TrimSpace(s.KeyFile)
	if keyFile == "" {
		return nil, errors.New("hopproof: SSH signing key file is required")
	}
	if strings.TrimSpace(principal) == "" {
		return nil, errors.New("hopproof: SSH signing principal is required")
	}
	command := exec.CommandContext(ctx, binary, "-Y", "sign", "-f", keyFile, "-n", SignatureDomain)
	command.Stdin = bytes.NewReader(message)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("hopproof: ssh-keygen sign: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	signature := bytes.TrimSpace(stdout.Bytes())
	if len(signature) == 0 {
		return nil, errors.New("hopproof: ssh-keygen returned an empty signature")
	}
	return append([]byte(nil), signature...), nil
}

// SSHKeygenVerifier verifies an SSHSIG against an OpenSSH allowed-signers file.
type SSHKeygenVerifier struct {
	Binary             string
	AllowedSignersFile string
}

func (v SSHKeygenVerifier) Verify(ctx context.Context, principal string, message, signature []byte) error {
	binary := strings.TrimSpace(v.Binary)
	if binary == "" {
		binary = "ssh-keygen"
	}
	allowed := strings.TrimSpace(v.AllowedSignersFile)
	if allowed == "" {
		return errors.New("hopproof: allowed-signers file is required")
	}
	principal = strings.TrimSpace(principal)
	if principal == "" {
		return errors.New("hopproof: signer principal is required")
	}
	temp, err := os.CreateTemp("", "weaverssh-hop-*.sshsig")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err := temp.Write(signature); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}

	command := exec.CommandContext(ctx, binary,
		"-Y", "verify",
		"-f", allowed,
		"-I", principal,
		"-n", SignatureDomain,
		"-s", name,
	)
	command.Stdin = bytes.NewReader(message)
	var stderr bytes.Buffer
	command.Stdout = &bytes.Buffer{}
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("hopproof: ssh-keygen verify: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}
