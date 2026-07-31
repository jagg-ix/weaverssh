package app

import (
	"path/filepath"
	"testing"
	"time"

	"weaverssh/flowcontrol"
)

func TestConfigReloadSynchronizesMQTTSSHAndGRPCBuffers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	config := DefaultConfig()
	config.Security.AuthCookie = "test-cookie"
	config.Server.BufferSize = 8 * 1024
	if err := config.SaveConfig(path); err != nil { t.Fatal(err) }
	manager, err := NewConfigManager(path)
	if err != nil { t.Fatal(err) }
	coordinator := flowcontrol.NewDefaultBufferCoordinator()
	if err := BindProtocolBufferCoordinator(manager, coordinator, 4); err != nil { t.Fatal(err) }
	initial := coordinator.Current()
	assertAlignedProtocolBuffers(t, initial.Buffers, 8*1024, 4)

	config.Server.BufferSize = 32 * 1024
	if err := config.SaveConfig(path); err != nil { t.Fatal(err) }
	if err := manager.Reload(); err != nil { t.Fatal(err) }
	deadline := time.Now().Add(2 * time.Second)
	for coordinator.Current().Generation == initial.Generation && time.Now().Before(deadline) { time.Sleep(10 * time.Millisecond) }
	updated := coordinator.Current()
	if updated.Generation == initial.Generation { t.Fatal("config reload did not advance protocol buffer generation") }
	assertAlignedProtocolBuffers(t, updated.Buffers, 32*1024, 4)
}

func assertAlignedProtocolBuffers(t *testing.T, buffers flowcontrol.ProtocolBuffers, frame, queue int) {
	t.Helper()
	if err := buffers.Validate(); err != nil { t.Fatal(err) }
	if buffers.FrameBytes != frame || buffers.QueueDepth != queue { t.Fatalf("unexpected authority settings: %+v", buffers) }
	if buffers.MQTTReadBufferBytes != frame || buffers.MQTTWriteBufferBytes != frame || buffers.SSHChannelFrameBytes != frame || buffers.GRPCReadBufferBytes != frame || buffers.GRPCWriteBufferBytes != frame {
		t.Fatalf("frame settings drifted: %+v", buffers)
	}
	window := frame * queue
	if buffers.MQTTMaxPacketBytes != window || buffers.SSHChannelWindowBytes != window || buffers.GRPCInitialWindowBytes != window || buffers.GRPCInitialConnWindowBytes != window || buffers.GRPCMaxMessageBytes != window {
		t.Fatalf("window settings drifted: %+v", buffers)
	}
}
