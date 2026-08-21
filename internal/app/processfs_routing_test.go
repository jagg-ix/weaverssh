package app

import (
	"testing"

	"weaverssh/authproof"
)

func TestProcessFSBrokerRequiresVFSAndExecutionCapabilities(t *testing.T) {
	base := authproof.NodeContext{Capabilities: []string{authproof.CapabilityNodeContext}}
	if processFSBrokerAuthorized(base) {
		t.Fatal("ProcessFS authorized without capabilities")
	}
	base.Capabilities = append(base.Capabilities, authproof.CapabilityVFSMesh)
	if processFSBrokerAuthorized(base) {
		t.Fatal("ProcessFS authorized without execution capability")
	}
	base.Capabilities = append(base.Capabilities, authproof.CapabilityContainerExec)
	if !processFSBrokerAuthorized(base) {
		t.Fatal("ProcessFS denied with VFS and container-exec capabilities")
	}
}
