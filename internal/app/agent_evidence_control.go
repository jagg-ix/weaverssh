package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"weaverssh/socketcontrol"
)

type AgentEvidenceControlConfig struct {
	Network   string
	Address   string
	TokenFile string
}

type AgentEvidenceControl struct {
	cancel   context.CancelFunc
	listener net.Listener
	done     chan error
	network  string
	address  string
	closeOnce sync.Once
	closeErr error
}

func StartAgentEvidenceControl(parent context.Context, runtime *AgentRuntimeWithEmbeddedImmuDB, config AgentEvidenceControlConfig) (*AgentEvidenceControl, error) {
	if runtime == nil || runtime.EvidenceJournal() == nil {
		return nil, errors.New("agent evidence control requires an embedded evidence runtime")
	}
	network := strings.ToLower(strings.TrimSpace(config.Network))
	if network == "" {
		network = "unix"
	}
	if network != "unix" && network != "tcp" {
		return nil, fmt.Errorf("agent evidence control network must be unix or tcp")
	}
	address := strings.TrimSpace(config.Address)
	if address == "" {
		return nil, errors.New("agent evidence control address is required")
	}
	if network == "tcp" && !agentEvidenceLoopback(address) {
		return nil, errors.New("agent evidence TCP control address must be loopback")
	}
	tokenFile := strings.TrimSpace(config.TokenFile)
	if tokenFile == "" {
		tokenFile = address + ".token"
	}
	token, err := loadOrCreateAgentEvidenceToken(tokenFile)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := os.MkdirAll(filepath.Dir(address), 0o700); err != nil {
			return nil, err
		}
		if info, err := os.Lstat(address); err == nil {
			if info.Mode()&os.ModeSocket == 0 {
				return nil, errors.New("agent evidence control path exists and is not a socket")
			}
			if err := os.Remove(address); err != nil {
				return nil, err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		if err := os.Chmod(address, 0o600); err != nil {
			_ = listener.Close()
			return nil, err
		}
	}
	ctx, cancel := context.WithCancel(parent)
	control := &AgentEvidenceControl{cancel: cancel, listener: listener, done: make(chan error, 1), network: network, address: address}
	server := &socketcontrol.Server{Token: token, Handler: func(requestCtx context.Context, request socketcontrol.Request) (any, error) {
		switch request.Action {
		case socketcontrol.ActionEvidenceStatus:
			return runtime.EvidenceStatus(), nil
		case socketcontrol.ActionEvidenceVerify:
			return runtime.VerifyEvidenceJournal(requestCtx)
		case socketcontrol.ActionEvidenceExport:
			exported := runtime.ExportEvidenceJournal()
			limit := 100
			if value := strings.TrimSpace(request.Config); value != "" {
				parsed, parseErr := strconv.Atoi(value)
				if parseErr != nil || parsed <= 0 || parsed > 1000 {
					return nil, errors.New("evidence export limit must be between 1 and 1000")
				}
				limit = parsed
			}
			if len(exported.Records) > limit {
				exported.Records = exported.Records[len(exported.Records)-limit:]
			}
			return exported, nil
		case socketcontrol.ActionEvidenceRemoteStatus:
			return runtime.RemoteEvidenceStatus(), nil
		case socketcontrol.ActionEvidenceRemoteFlush:
			return runtime.FlushRemoteEvidence(requestCtx)
		case socketcontrol.ActionEvidenceSnapshot:
			return runtime.CreateEvidenceSnapshot()
		default:
			return nil, socketcontrol.ErrInvalid
		}
	}}
	go func() { control.done <- server.Serve(ctx, listener) }()
	return control, nil
}

func (c *AgentEvidenceControl) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.cancel()
		if c.listener != nil {
			c.closeErr = c.listener.Close()
		}
		if c.network == "unix" {
			if err := os.Remove(c.address); err != nil && !errors.Is(err, os.ErrNotExist) && c.closeErr == nil {
				c.closeErr = err
			}
		}
	})
	return c.closeErr
}

func (c *AgentEvidenceControl) Wait() error {
	if c == nil || c.done == nil {
		return nil
	}
	return <-c.done
}

func loadOrCreateAgentEvidenceToken(path string) ([]byte, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("agent evidence token file must not be a symbolic link")
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil, readErr
		}
		token, decodeErr := socketcontrol.DecodeToken(strings.TrimSpace(string(data)))
		if decodeErr != nil {
			return nil, decodeErr
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		return token, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	token, err := socketcontrol.NewToken()
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := file.WriteString(socketcontrol.EncodeToken(token) + "\n"); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	return token, nil
}

func agentEvidenceLoopback(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
