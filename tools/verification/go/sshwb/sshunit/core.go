package sshunit

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HostKeyPolicy int

const (
	HostKeyStrict HostKeyPolicy = iota
	HostKeyAcceptNew
	HostKeyInsecure
)

func ParseHostKeyPolicy(raw string) (HostKeyPolicy, error) {
	v := strings.TrimSpace(strings.ToLower(raw))
	switch v {
	case "", "strict":
		return HostKeyStrict, nil
	case "accept-new", "acceptnew":
		return HostKeyAcceptNew, nil
	case "insecure", "off", "no":
		return HostKeyInsecure, nil
	default:
		return HostKeyStrict, fmt.Errorf("invalid_hostkey_policy:%s", raw)
	}
}

func (p HostKeyPolicy) SSHOptions() []string {
	switch p {
	case HostKeyAcceptNew:
		return []string{"-o", "StrictHostKeyChecking=accept-new"}
	case HostKeyInsecure:
		return []string{
			"-o", "StrictHostKeyChecking=no",
			"-o", "UserKnownHostsFile=/dev/null",
		}
	default:
		return []string{"-o", "StrictHostKeyChecking=yes"}
	}
}

func BuildSSHArgs(
	user string,
	host string,
	port int,
	identityFile string,
	policy HostKeyPolicy,
	forwardX11 bool,
	remoteCommand string,
) ([]string, error) {
	u := strings.TrimSpace(user)
	h := strings.TrimSpace(host)
	cmd := strings.TrimSpace(remoteCommand)
	if u == "" {
		return nil, errors.New("missing_user")
	}
	if h == "" {
		return nil, errors.New("missing_host")
	}
	if port <= 0 || port > 65535 {
		return nil, errors.New("invalid_port")
	}
	if cmd == "" {
		return nil, errors.New("missing_command")
	}
	args := []string{"ssh", "-p", strconv.Itoa(port)}
	args = append(args, policy.SSHOptions()...)
	if strings.TrimSpace(identityFile) != "" {
		args = append(args, "-i", strings.TrimSpace(identityFile))
	}
	if forwardX11 {
		args = append(args, "-X", "-o", "ForwardX11=yes")
	}
	args = append(args, fmt.Sprintf("%s@%s", u, h), cmd)
	return args, nil
}

func ParseEndpoint(raw string, defaultPort int) (string, int, error) {
	token := strings.TrimSpace(raw)
	if token == "" {
		return "", 0, errors.New("missing_endpoint")
	}
	if defaultPort <= 0 || defaultPort > 65535 {
		return "", 0, errors.New("invalid_default_port")
	}
	if strings.Contains(token, "://") {
		return "", 0, errors.New("scheme_not_supported")
	}
	if strings.HasPrefix(token, "[") {
		end := strings.Index(token, "]")
		if end <= 1 {
			return "", 0, errors.New("invalid_endpoint")
		}
		host := strings.TrimSpace(token[1:end])
		rest := strings.TrimSpace(token[end+1:])
		if rest == "" {
			return host, defaultPort, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, errors.New("invalid_endpoint")
		}
		port, convErr := strconv.Atoi(strings.TrimSpace(rest[1:]))
		if convErr != nil || port <= 0 || port > 65535 {
			return "", 0, errors.New("invalid_port")
		}
		return host, port, nil
	}
	if strings.Contains(token, ":") {
		idx := strings.LastIndex(token, ":")
		if idx <= 0 || idx == len(token)-1 {
			return "", 0, errors.New("invalid_endpoint")
		}
		host := strings.TrimSpace(token[:idx])
		portStr := strings.TrimSpace(token[idx+1:])
		if host == "" {
			return "", 0, errors.New("missing_host")
		}
		port, convErr := strconv.Atoi(portStr)
		if convErr != nil || port <= 0 || port > 65535 {
			return "", 0, errors.New("invalid_port")
		}
		return host, port, nil
	}
	return token, defaultPort, nil
}

func VerifyHostKeyFingerprint(expected string, got string) error {
	e := strings.TrimSpace(expected)
	g := strings.TrimSpace(got)
	if e == "" {
		return errors.New("missing_expected_fingerprint")
	}
	if g == "" {
		return errors.New("missing_actual_fingerprint")
	}
	if e != g {
		return errors.New("hostkey_mismatch")
	}
	return nil
}

type Transport interface {
	Open() error
	Close() error
	Write([]byte) error
}

type ChannelState string

const (
	ChannelNew    ChannelState = "new"
	ChannelOpen   ChannelState = "open"
	ChannelClosed ChannelState = "closed"
)

type Channel struct {
	mu    sync.Mutex
	state ChannelState
	tx    Transport
}

func NewChannel(tx Transport) *Channel {
	return &Channel{state: ChannelNew, tx: tx}
}

func (c *Channel) State() ChannelState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *Channel) Open() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != ChannelNew {
		return errors.New("channel_not_new")
	}
	if err := c.tx.Open(); err != nil {
		return err
	}
	c.state = ChannelOpen
	return nil
}

func (c *Channel) OpenWithRetry(maxAttempts int, pause time.Duration) error {
	if maxAttempts <= 0 {
		return errors.New("invalid_attempt_count")
	}
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		lastErr = c.Open()
		if lastErr == nil {
			return nil
		}
		if i < maxAttempts-1 && pause > 0 {
			time.Sleep(pause)
		}
		// If the first open failed, the channel remains in "new"; retries are valid.
	}
	return lastErr
}

func (c *Channel) Send(payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != ChannelOpen {
		return errors.New("channel_not_open")
	}
	if len(payload) == 0 {
		return errors.New("empty_payload")
	}
	return c.tx.Write(payload)
}

func (c *Channel) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state == ChannelClosed {
		return nil
	}
	if c.state == ChannelNew {
		c.state = ChannelClosed
		return nil
	}
	if err := c.tx.Close(); err != nil {
		return err
	}
	c.state = ChannelClosed
	return nil
}

type FakeTransport struct {
	mu          sync.Mutex
	OpenErrors  []error
	WriteErrors []error
	CloseError  error
	OpenCalls   int
	WriteCalls  int
	CloseCalls  int
	Payloads    [][]byte
}

func (f *FakeTransport) Open() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.OpenCalls++
	if len(f.OpenErrors) == 0 {
		return nil
	}
	err := f.OpenErrors[0]
	f.OpenErrors = f.OpenErrors[1:]
	return err
}

func (f *FakeTransport) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.CloseCalls++
	return f.CloseError
}

func (f *FakeTransport) Write(payload []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.WriteCalls++
	if len(f.WriteErrors) > 0 {
		err := f.WriteErrors[0]
		f.WriteErrors = f.WriteErrors[1:]
		if err != nil {
			return err
		}
	}
	buf := make([]byte, len(payload))
	copy(buf, payload)
	f.Payloads = append(f.Payloads, buf)
	return nil
}
