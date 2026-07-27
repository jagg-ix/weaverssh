package socketcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"weaverssh/socketengine"
)

func unusedLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func writeEngineConfig(t *testing.T, path, listen string) {
	t.Helper()
	config := socketengine.Config{
		Version: socketengine.ConfigVersion,
		Routes: []socketengine.Route{{
			Name: "route",
			Listen: "tcp://" + listen,
			Node: "node-a",
			Network: "tcp",
			Address: "127.0.0.1:9",
		}},
	}
	payload, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorReloadsDisjointListeners(t *testing.T) {
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first.json")
	secondPath := filepath.Join(directory, "second.json")
	writeEngineConfig(t, firstPath, unusedLoopbackAddress(t))
	writeEngineConfig(t, secondPath, unusedLoopbackAddress(t))

	factory := func(config socketengine.Config) (*socketengine.Engine, error) {
		return socketengine.New(config, func(context.Context, socketengine.Route) (net.Conn, error) {
			return nil, errors.New("not dialed in supervisor test")
		}, nil)
	}
	supervisor, err := NewSupervisor(SupervisorConfig{
		ConfigPath: firstPath,
		NewEngine: factory,
		ShutdownTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	first := supervisor.Status()
	if first.Generation != 1 || len(first.Plan.Addresses) != 1 {
		t.Fatalf("first status=%+v", first)
	}
	reloaded, err := supervisor.Reload(context.Background(), secondPath)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Generation != 2 || reloaded.ConfigSHA256 == first.ConfigSHA256 {
		t.Fatalf("reloaded status=%+v first=%+v", reloaded, first)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := supervisor.Stop(stopCtx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSupervisorInvalidReloadKeepsGeneration(t *testing.T) {
	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid.json")
	invalidPath := filepath.Join(directory, "invalid.json")
	writeEngineConfig(t, validPath, unusedLoopbackAddress(t))
	if err := os.WriteFile(invalidPath, []byte(`{"version":"wrong"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	factory := func(config socketengine.Config) (*socketengine.Engine, error) {
		return socketengine.New(config, func(context.Context, socketengine.Route) (net.Conn, error) {
			return nil, errors.New("not dialed")
		}, nil)
	}
	supervisor, err := NewSupervisor(SupervisorConfig{ConfigPath: validPath, NewEngine: factory, ShutdownTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	before := supervisor.Status()
	if _, err := supervisor.Reload(context.Background(), invalidPath); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	after := supervisor.Status()
	if after.Generation != before.Generation || after.ConfigSHA256 != before.ConfigSHA256 || after.LastReloadError == "" {
		t.Fatalf("after=%+v before=%+v", after, before)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	_ = supervisor.Stop(stopCtx)
}
