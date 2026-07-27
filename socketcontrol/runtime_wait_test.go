package socketcontrol

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"weaverssh/socketengine"
)

func testRuntimeEngine(config socketengine.Config) (*socketengine.Engine, error) {
	return socketengine.New(config, func(context.Context, socketengine.Route) (net.Conn, error) {
		return nil, errors.New("test dial disabled")
	}, nil)
}

func TestWaitRuntimeReportsUnexpectedExit(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "engine.json")
	writeEngineConfig(t, configPath, unusedLoopbackAddress(t))
	supervisor, err := NewSupervisor(SupervisorConfig{
		ConfigPath: configPath,
		NewEngine: testRuntimeEngine,
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
	supervisor.mu.RLock()
	current := supervisor.current
	supervisor.mu.RUnlock()
	if current == nil {
		t.Fatal("missing active generation")
	}
	current.cancel()
	waitErr := supervisor.WaitRuntime()
	if waitErr == nil || !strings.Contains(waitErr.Error(), "stopped unexpectedly") {
		t.Fatalf("WaitRuntime error=%v", waitErr)
	}
}

func TestWaitRuntimeSurvivesReload(t *testing.T) {
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first.json")
	secondPath := filepath.Join(directory, "second.json")
	writeEngineConfig(t, firstPath, unusedLoopbackAddress(t))
	writeEngineConfig(t, secondPath, unusedLoopbackAddress(t))
	supervisor, err := NewSupervisor(SupervisorConfig{
		ConfigPath: firstPath,
		NewEngine: testRuntimeEngine,
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
	waitDone := make(chan error, 1)
	go func() { waitDone <- supervisor.WaitRuntime() }()
	if _, err := supervisor.Reload(context.Background(), secondPath); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waitDone:
		t.Fatalf("WaitRuntime returned during reload: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer stopCancel()
	if err := supervisor.Stop(stopCtx); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("WaitRuntime after stop: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WaitRuntime did not return after stop")
	}
}
