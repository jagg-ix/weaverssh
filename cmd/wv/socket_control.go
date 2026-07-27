package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"weaverssh/sessionbroker"
	"weaverssh/sessiontcp"
	"weaverssh/socketcontrol"
	"weaverssh/socketengine"
)

func cmdSocketEngineServe(args []string) int {
	fs := flag.NewFlagSet("socket-engine serve", flag.ContinueOnError)
	configPath := fs.String("config", "", "socket engine JSON configuration")
	controlNetwork := fs.String("control-network", defaultSocketControlNetwork(), "control IPC network: unix or tcp")
	controlAddress := fs.String("control", defaultSocketControlPath(), "control socket path or address")
	tokenFile := fs.String("token-file", "", "HMAC control token file")
	jsonOut := fs.Bool("json", false, "emit startup metadata as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: wv socket-engine serve --config CONFIG.json [--control PATH] [--token-file FILE]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 || strings.TrimSpace(*configPath) == "" || strings.TrimSpace(*controlAddress) == "" {
		fs.Usage()
		return 2
	}
	network := strings.ToLower(strings.TrimSpace(*controlNetwork))
	if network != "unix" && network != "tcp" {
		fmt.Fprintln(os.Stderr, "socket-engine serve: --control-network must be unix or tcp")
		return 2
	}
	if network == "unix" && runtime.GOOS == "windows" {
		fmt.Fprintln(os.Stderr, "socket-engine serve: Unix control sockets are unavailable on Windows; use --control-network tcp")
		return 2
	}
	if network == "tcp" && !isLoopbackListen(*controlAddress) {
		fmt.Fprintln(os.Stderr, "socket-engine serve: TCP control address must be loopback")
		return 2
	}
	resolvedTokenFile := strings.TrimSpace(*tokenFile)
	if resolvedTokenFile == "" {
		resolvedTokenFile = defaultSocketControlTokenPath(network, *controlAddress)
	}
	token, created, err := loadOrCreateSocketControlToken(resolvedTokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket-engine serve: control token: %v\n", err)
		return 1
	}
	if network == "unix" {
		if err := prepareSocketControlPath(*controlAddress); err != nil {
			fmt.Fprintf(os.Stderr, "socket-engine serve: control socket: %v\n", err)
			return 1
		}
	}
	listener, err := net.Listen(network, strings.TrimSpace(*controlAddress))
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket-engine serve: control listen: %v\n", err)
		return 1
	}
	defer listener.Close()
	if network == "unix" {
		_ = os.Chmod(strings.TrimSpace(*controlAddress), 0o600)
		defer os.Remove(strings.TrimSpace(*controlAddress))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var droppedErrors atomic.Uint64
	errorEvents := make(chan socketEngineErrorEvent, 128)
	go consumeSocketEngineErrors(ctx, errorEvents, *jsonOut)
	factory := func(config socketengine.Config) (*socketengine.Engine, error) {
		return socketengine.New(
			config,
			func(openCtx context.Context, route socketengine.Route) (net.Conn, error) {
				state, err := sessionbroker.ActiveState()
				if err != nil {
					return nil, err
				}
				return sessiontcp.DialBroker(openCtx, state.Socket, route.Node, route.Network, route.Address)
			},
			func(route socketengine.Route, remote string, err error) {
				select {
				case errorEvents <- socketEngineErrorEvent{Route: route, Remote: remote, Err: err}:
				default:
					droppedErrors.Add(1)
				}
			},
		)
	}
	supervisor, err := socketcontrol.NewSupervisor(socketcontrol.SupervisorConfig{
		ConfigPath: strings.TrimSpace(*configPath),
		NewEngine:  factory,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket-engine serve: supervisor: %v\n", err)
		return 1
	}
	if err := supervisor.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "socket-engine serve: start: %v\n", err)
		return 1
	}
	controlServer := &socketcontrol.Server{Token: token, Handler: supervisor.Handler}
	controlDone := make(chan error, 1)
	go func() { controlDone <- controlServer.Serve(ctx, listener) }()
	status := supervisor.Status()
	startup := map[string]any{
		"event":           "ready",
		"control_network": network,
		"control_address": listener.Addr().String(),
		"token_file":      resolvedTokenFile,
		"token_created":   created,
		"generation":      status.Generation,
		"config_sha256":   status.ConfigSHA256,
		"listeners":       status.Plan.Addresses,
		"binding_refresh": true,
	}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(startup)
	} else {
		fmt.Printf("socket-engine supervisor ready generation=%d control=%s:%s token=%s\n", status.Generation, network, listener.Addr(), resolvedTokenFile)
		fmt.Printf("config-sha256: %s\nbinding-refresh: enabled\n", status.ConfigSHA256)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- supervisor.WaitRuntime() }()
	select {
	case err := <-waitDone:
		stop()
		if err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintf(os.Stderr, "socket-engine serve: %v\n", err)
			return 1
		}
	case err := <-controlDone:
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "socket-engine serve: control server: %v\n", err)
			return 1
		}
	case <-ctx.Done():
		stopCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = supervisor.Stop(stopCtx)
		cancel()
	}
	_ = droppedErrors.Load()
	return 0
}

func cmdSocketEngineControl(action string, args []string) int {
	fs := flag.NewFlagSet("socket-engine "+action, flag.ContinueOnError)
	controlNetwork := fs.String("control-network", defaultSocketControlNetwork(), "control IPC network")
	controlAddress := fs.String("control", defaultSocketControlPath(), "control socket path or address")
	tokenFile := fs.String("token-file", "", "HMAC control token file")
	configPath := fs.String("config", "", "replacement config path for reload")
	timeout := fs.Duration("timeout", 15*time.Second, "control call timeout")
	jsonOut := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		return 2
	}
	network := strings.ToLower(strings.TrimSpace(*controlNetwork))
	resolvedTokenFile := strings.TrimSpace(*tokenFile)
	if resolvedTokenFile == "" {
		resolvedTokenFile = defaultSocketControlTokenPath(network, *controlAddress)
	}
	token, err := readSocketControlToken(resolvedTokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket-engine %s: token: %v\n", action, err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, err := socketcontrol.Call(ctx, network, strings.TrimSpace(*controlAddress), token, action, *configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket-engine %s: %v\n", action, err)
		return 1
	}
	var status socketcontrol.Status
	if err := socketcontrol.DecodePayload(response, &status); err != nil {
		fmt.Fprintf(os.Stderr, "socket-engine %s: %v\n", action, err)
		return 1
	}
	if *jsonOut {
		return printJSON(status)
	}
	printSocketControlStatus(status)
	return 0
}

func printSocketControlStatus(status socketcontrol.Status) {
	fmt.Printf(
		"generation: %d\nconfig: %s\nconfig-sha256: %s\nactive: %d\naccepted: %d\nrejected: %d\nbytes-in: %d\nbytes-out: %d\nstopping: %t\n",
		status.Generation,
		status.ConfigPath,
		status.ConfigSHA256,
		status.Stats.Active,
		status.Stats.Accepted,
		status.Stats.Rejected,
		status.Stats.BytesIn,
		status.Stats.BytesOut,
		status.Stopping,
	)
	if status.LastReloadError != "" {
		fmt.Printf("last-reload-error: %s\n", status.LastReloadError)
	}
}

func defaultSocketControlNetwork() string {
	if runtime.GOOS == "windows" {
		return "tcp"
	}
	return "unix"
}

func defaultSocketControlPath() string {
	if runtime.GOOS == "windows" {
		return "127.0.0.1:19741"
	}
	if runtimeDir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); runtimeDir != "" {
		return filepath.Join(runtimeDir, "weaverssh", "socket-engine-control.sock")
	}
	identity := strings.TrimSpace(os.Getenv("USER"))
	if identity == "" {
		identity = strings.TrimSpace(os.Getenv("USERNAME"))
	}
	if identity == "" {
		identity = "local"
	}
	identity = sanitizeSocketControlIdentity(identity)
	return filepath.Join(os.TempDir(), "weaverssh-"+identity, "socket-engine-control.sock")
}

func defaultSocketControlTokenPath(network, address string) string {
	if strings.EqualFold(strings.TrimSpace(network), "unix") {
		return strings.TrimSpace(address) + ".token"
	}
	if runtimeDir := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); runtimeDir != "" {
		return filepath.Join(runtimeDir, "weaverssh", "socket-engine-control.token")
	}
	identity := strings.TrimSpace(os.Getenv("USER"))
	if identity == "" {
		identity = strings.TrimSpace(os.Getenv("USERNAME"))
	}
	if identity == "" {
		identity = "local"
	}
	return filepath.Join(os.TempDir(), "weaverssh-"+sanitizeSocketControlIdentity(identity), "socket-engine-control.token")
}

func sanitizeSocketControlIdentity(value string) string {
	var builder strings.Builder
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			builder.WriteRune(r)
		}
	}
	if builder.Len() == 0 {
		return "local"
	}
	return builder.String()
}

func loadOrCreateSocketControlToken(path string) ([]byte, bool, error) {
	if token, err := readSocketControlToken(path); err == nil {
		return token, false, nil
	} else if !os.IsNotExist(unwrapPathError(err)) {
		return nil, false, err
	}
	token, err := socketcontrol.NewToken()
	if err != nil {
		return nil, false, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, false, err
	}
	_, writeErr := fmt.Fprintln(file, socketcontrol.EncodeToken(token))
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return nil, false, writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return nil, false, closeErr
	}
	return token, true, nil
}

func readSocketControlToken(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("control token is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("control token must not be group- or world-accessible")
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return socketcontrol.DecodeToken(strings.TrimSpace(string(payload)))
}

func prepareSocketControlPath(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %s", path)
	}
	return os.Remove(path)
}

func unwrapPathError(err error) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err
	}
	return err
}
