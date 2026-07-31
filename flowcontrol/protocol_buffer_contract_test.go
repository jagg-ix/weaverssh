package flowcontrol

import (
	"os"
	"strings"
	"testing"
)

func TestProtocolBufferSynchronizationArtifactsRemainConnected(t *testing.T) {
	files := map[string][]string{
		"protocol_buffers.go": {"ProtocolBufferContractVersion", "BufferCoordinator", "PrepareProtocolBuffers", "CommitProtocolBuffers", "ErrStaleBufferUpdate"},
		"../pubsub/mqtt_buffer_sync.go": {"MQTTBufferFactory", "MQTTReadBufferBytes", "MQTTWriteBufferBytes", "BufferGeneration"},
		"../pubsub/mqtt_buffer_updates.go": {"PublishProtocolBufferUpdate", "ApplyProtocolBufferMessage", "weaverssh/settings/protocol-buffers/v1"},
		"../sessionmux/buffer_sync.go": {"BufferSyncedMux", "SSHChannelWindowBytes", "cannot shrink SSH channel buffers"},
		"../sessionmux/buffer_update_wire.go": {"ProtocolBufferControlMetadata", "ApplyProtocolBufferControlStream"},
		"../grpcbuffer/runtime.go": {"InitialConnWindowBytes", "MaxSendMessageBytes", "IsStale"},
		"../grpcbuffer/update_service.go": {"UpdateService", "DecodeBufferUpdate"},
		"../internal/app/protocol_buffer_sync.go": {"BindProtocolBufferCoordinator", "Server.BufferSize"},
		"../docs/architecture/protocol-buffer-sync.md": {"```mermaid", "Atomic changes", "MQTT", "SSH logical channels", "gRPC", "failed participant preparation"},
	}
	for path, required := range files {
		data, err := os.ReadFile(path)
		if err != nil { t.Errorf("read %s: %v", path, err); continue }
		text := string(data)
		for _, phrase := range required {
			if !strings.Contains(text, phrase) { t.Errorf("%s missing %q", path, phrase) }
		}
	}
}
