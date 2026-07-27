package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"strings"
	"time"

	"weaverssh/authproof"
	"weaverssh/sessionbroker"
	"weaverssh/sessionlink"
)

type ReconnectPolicy struct {
	MinDelay time.Duration
	MaxDelay time.Duration
	ResetAfter time.Duration
	Jitter float64
}

func (p ReconnectPolicy) Normalized() ReconnectPolicy {
	out := p
	if out.MinDelay <= 0 { out.MinDelay = time.Second }
	if out.MaxDelay <= 0 { out.MaxDelay = 30 * time.Second }
	if out.MaxDelay < out.MinDelay { out.MaxDelay = out.MinDelay }
	if out.ResetAfter <= 0 { out.ResetAfter = time.Minute }
	if out.Jitter < 0 { out.Jitter = 0 }
	if out.Jitter > 1 { out.Jitter = 1 }
	return out
}

func (p ReconnectPolicy) Delay(failures uint) time.Duration {
	p = p.Normalized()
	if failures == 0 { return 0 }
	shift := failures - 1; if shift > 62 { shift = 62 }
	factor := uint64(1) << shift
	base := p.MinDelay
	if factor > 0 && uint64(base) > uint64(p.MaxDelay)/factor { base = p.MaxDelay } else { base = time.Duration(uint64(base)*factor); if base > p.MaxDelay { base = p.MaxDelay } }
	if p.Jitter == 0 || base <= 0 { return base }
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil { return base }
	unit := float64(binary.BigEndian.Uint64(raw[:])) / float64(math.MaxUint64)
	multiplier := 1 + ((unit*2)-1)*p.Jitter
	jittered := time.Duration(float64(base)*multiplier)
	if jittered < 0 { return 0 }
	if jittered > p.MaxDelay { return p.MaxDelay }
	return jittered
}

type ReconnectEvent struct { Attempt uint; StartedAt time.Time; EndedAt time.Time; Err error; NextDelay time.Duration }

func RunReconnectLoop(ctx context.Context, reconnect bool, policy ReconnectPolicy, attempt func(context.Context) error, onEvent func(ReconnectEvent)) error {
	if ctx == nil { ctx = context.Background() }
	if attempt == nil { return errors.New("reconnect loop: nil attempt") }
	policy = policy.Normalized()
	var failures uint
	var attemptNumber uint
	for {
		if err := ctx.Err(); err != nil { return nil }
		attemptNumber++
		started := time.Now(); err := attempt(ctx); ended := time.Now()
		if ctx.Err() != nil { return nil }
		if !reconnect { return err }
		if ended.Sub(started) >= policy.ResetAfter { failures = 0 }
		failures++
		delay := policy.Delay(failures)
		if onEvent != nil { onEvent(ReconnectEvent{Attempt: attemptNumber, StartedAt: started, EndedAt: ended, Err: err, NextDelay: delay}) }
		timer := time.NewTimer(delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() { select { case <-timer.C: default: } }
			return nil
		}
	}
}

func StartLeaseRenewal(parent context.Context, lease time.Duration, renew func(context.Context, time.Time) error, onError func(error)) func() {
	if parent == nil { parent = context.Background() }
	ctx, cancel := context.WithCancel(parent)
	if lease <= 0 || renew == nil { return cancel }
	interval := lease/3
	if interval < time.Second { interval = time.Second }
	go func() {
		ticker := time.NewTicker(interval); defer ticker.Stop()
		for {
			select {
			case <-ctx.Done(): return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(ctx, interval)
				err := renew(renewCtx, time.Now().Add(lease)); renewCancel()
				if err != nil && onError != nil { onError(err) }
			}
		}
	}()
	return cancel
}

type CommandSupervisorConfig struct {
	Args []string
	Env []string
	Stdin io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Reconnect bool
	Policy ReconnectPolicy
	OnEvent func(ReconnectEvent)
}

func RunCommandSupervisor(ctx context.Context, config CommandSupervisorConfig) error {
	if len(config.Args) == 0 { return errors.New("command supervisor: missing command") }
	args := append([]string(nil), config.Args...)
	environment := append([]string(nil), config.Env...)
	return RunReconnectLoop(ctx, config.Reconnect, config.Policy, func(attemptCtx context.Context) error {
		command := exec.CommandContext(attemptCtx, args[0], args[1:]...)
		command.Env = environment; command.Stdin = config.Stdin; command.Stdout = config.Stdout; command.Stderr = config.Stderr
		return command.Run()
	}, config.OnEvent)
}

func LoadSignedReconnectIdentityFile(path string) (authproof.SignedReconnectIdentity, error) {
	var signed authproof.SignedReconnectIdentity
	data, err := os.ReadFile(strings.TrimSpace(path)); if err != nil { return signed, err }
	if err := json.Unmarshal(data, &signed); err != nil { return signed, err }
	return signed, nil
}

func LoadEd25519PrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(strings.TrimSpace(path)); if err != nil { return nil, err }
	return authproof.DecodePrivateKey(strings.TrimSpace(string(data)))
}

type AttachGeneration struct { Attached *AttachedSession; Token sessionlink.Token; Snapshot sessionlink.Snapshot }
type AttachGenerationReadyFunc func(AttachGeneration) (func(error), error)

type AttachSupervisorConfig struct {
	Attach AttachConfig
	AttachFunc func(context.Context, AttachConfig) (*AttachedSession, error)
	RuntimeProofProvider RuntimeProofProvider
	Router *sessionbroker.LinkRouter
	Lease time.Duration
	Reconnect bool
	Policy ReconnectPolicy
	OnReady AttachGenerationReadyFunc
	OnEvent func(ReconnectEvent)
}

type AttachSupervisor struct { config AttachSupervisorConfig; ready chan AttachGeneration; done chan error }

func NewAttachSupervisor(config AttachSupervisorConfig) (*AttachSupervisor, error) {
	if config.Router == nil { return nil, errors.New("attach supervisor: logical link router is required") }
	if config.Lease <= 0 || config.Lease > sessionlink.MaxLease { return nil, sessionlink.ErrInvalidLease }
	if config.Attach.RuntimeProof != nil && config.RuntimeProofProvider != nil { return nil, errors.New("attach supervisor: static runtime proof and refresh provider are mutually exclusive") }
	if config.Reconnect && config.Attach.RuntimeProof != nil { return nil, errors.New("attach supervisor: reconnect cannot replay a static runtime proof; configure a refresh signer") }
	if config.Reconnect && config.RuntimeProofProvider == nil {
		provider, enabled, err := RuntimeProofProviderFromEnvironment()
		if err != nil { return nil, err }
		if enabled { config.RuntimeProofProvider = provider }
	}
	if config.RuntimeProofProvider != nil { config.AttachFunc = attachFuncWithRuntimeProofProvider(config.AttachFunc, config.RuntimeProofProvider) }
	return &AttachSupervisor{config: config, ready: make(chan AttachGeneration, 1), done: make(chan error, 1)}, nil
}

func (s *AttachSupervisor) Ready() <-chan AttachGeneration { if s == nil { return nil }; return s.ready }
func (s *AttachSupervisor) Done() <-chan error { if s == nil { return nil }; return s.done }
func (s *AttachSupervisor) Start(ctx context.Context) { if s == nil { return }; go func() { s.done <- s.Run(ctx) }() }

func (s *AttachSupervisor) Run(ctx context.Context) error {
	if s == nil { return errors.New("attach supervisor: nil supervisor") }
	attach := s.config.AttachFunc; if attach == nil { attach = AttachDynamicSession }
	return RunReconnectLoop(ctx, s.config.Reconnect, s.config.Policy, func(attemptCtx context.Context) error {
		attached, err := attach(attemptCtx, s.config.Attach)
		if err != nil { return err }
		if attached.LinkID != s.config.Router.LinkID() { _ = attached.CloseTransport(); return fmt.Errorf("attach supervisor: logical link mismatch: expected %s got %s", s.config.Router.LinkID(), attached.LinkID) }
		token, snapshot, _, err := s.config.Router.Publish(attached.TransportID, s.config.Lease, attached.OpenBroker)
		if err != nil { _ = attached.CloseTransport(); return err }
		generation := AttachGeneration{Attached: attached, Token: token, Snapshot: snapshot}
		var cleanup func(error)
		if s.config.OnReady != nil {
			cleanup, err = s.config.OnReady(generation)
			if err != nil { s.config.Router.Withdraw(token, err); _ = attached.CloseTransport(); return err }
		}
		select { case s.ready <- generation: default: }
		var terminal error
		select {
		case terminal = <-attached.ServiceDone(): if terminal == nil { terminal = errors.New("attach supervisor: transport ended") }
		case <-attemptCtx.Done(): terminal = attemptCtx.Err()
		}
		if cleanup != nil { cleanup(terminal) }
		s.config.Router.Withdraw(token, terminal); _ = attached.CloseTransport()
		if attemptCtx.Err() != nil { return nil }
		return terminal
	}, s.config.OnEvent)
}
