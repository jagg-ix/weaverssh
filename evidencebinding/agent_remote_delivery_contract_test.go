package evidencebinding

import (
	"os"
	"strings"
	"testing"
)

func TestAgentRemoteDeliveryArtifactsRemainConnected(t *testing.T) {
	files := map[string][]string{
		"agent_remote_queue.go": {
			"AgentRemoteAnchorQueue", "AgentRemoteQueueVersion", "AgentRemoteDelivery",
			"MinBackoff", "mergeAnchorReceipts", "persistState", "CloseAnchorProviders",
		},
		"agent_snapshot.go": {
			"AgentJournalSnapshot", "VerifyAgentJournalSnapshot", "agentSnapshotDomain",
			"SnapshotWithRemote", "PayloadSHA256",
		},
		"../internal/app/agent_remote_delivery.go": {
			"WEAVERSSH_AGENT_REMOTE_PROVIDERS", "WEAVERSSH_AGENT_REMOTE_QUEUE",
			"OpenAgentRemoteDelivery", "embedded-immudb",
		},
		"../internal/app/agent_evidence_control.go": {
			"ActionEvidenceRemoteStatus", "ActionEvidenceRemoteFlush", "ActionEvidenceSnapshot",
		},
		"../cmd/wv/agent_evidence.go": {
			"remote-status", "remote-flush", "snapshot-verify", "writePrivateJSON",
		},
		"../docs/architecture/agent-evidence-remote-delivery.md": {
			"```mermaid", "Durable delivery flow", "not an independent witness", "Offline verification",
		},
	}
	for path, required := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}
		text := string(data)
		for _, phrase := range required {
			if !strings.Contains(text, phrase) {
				t.Errorf("%s missing %q", path, phrase)
			}
		}
	}
}
