package app

import (
	"fmt"
	"log"

	"weaverssh/flowcontrol"
)

// ProtocolBuffersFromConfig treats server.buffer_size as the authoritative
// application frame size. Every MQTT, SSH-channel, and gRPC value is derived
// from it and the selected queue depth rather than reusing independent defaults.
func ProtocolBuffersFromConfig(config *Config, queueDepth int) flowcontrol.ProtocolBuffers {
	if config == nil { return flowcontrol.ProtocolBuffersFromProfile(flowcontrol.DefaultProfile()) }
	return flowcontrol.ProtocolBuffersFromFrame(config.Server.BufferSize, queueDepth)
}

// BindProtocolBufferCoordinator applies the current configuration immediately
// and reapplies it after every ConfigManager reload. The existing Watch callback
// historically receives the previous config, so this binding intentionally
// reads ConfigManager.GetConfig after the atomic reload.
func BindProtocolBufferCoordinator(manager *ConfigManager, coordinator *flowcontrol.BufferCoordinator, queueDepth int) error {
	if manager == nil || coordinator == nil { return fmt.Errorf("config manager and protocol buffer coordinator are required") }
	apply := func() error {
		next := ProtocolBuffersFromConfig(manager.GetConfig(), queueDepth)
		current := coordinator.Current()
		if current.Buffers.Normalized() == next.Normalized() { return nil }
		_, err := coordinator.Update(next)
		return err
	}
	if err := apply(); err != nil { return err }
	manager.Watch(func(_ *Config) {
		if err := apply(); err != nil { log.Printf("protocol buffer config reload rejected: %v", err) }
	})
	return nil
}
