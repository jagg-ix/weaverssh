package containerstream

import (
	"strings"
	"testing"
)

func TestProcessFSOpenMetadataBindsBrokerProvenanceOnce(t *testing.T) {
	targetURI := "vfs://container/node-a/pod-a/.wv/processes?provider=podman"
	raw, err := NewProcessFSOpenMetadata("node-a", targetURI)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := ParseProcessFSOpenMetadata(raw)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SourceNode != "" || metadata.SourceBinding != "" || metadata.ChainSHA256 != "" {
		t.Fatalf("client metadata contains provenance: %+v", metadata)
	}
	chain := strings.Repeat("a", 64)
	bound, err := BindProcessFSSource(raw, "workstation", "binding-a", chain, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	forwarded, err := BindProcessFSSource(bound, "jump", "binding-b", chain, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err = ParseProcessFSOpenMetadata(forwarded)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.SourceNode != "workstation" || metadata.SourceBinding != "binding-a" || metadata.ChainSHA256 != chain {
		t.Fatalf("forwarder rewrote provenance: %+v", metadata)
	}
}

func TestProcessFSOpenMetadataRejectsRouteMismatchAndForgedSource(t *testing.T) {
	raw, err := NewProcessFSOpenMetadata("node-a", "vfs://container/node-a/pod-a/.wv/processes")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BindProcessFSSource(raw, "workstation", "binding-a", strings.Repeat("a", 64), "node-b"); err == nil {
		t.Fatal("route mismatch was accepted")
	}
	metadata, err := ParseProcessFSOpenMetadata(raw)
	if err != nil {
		t.Fatal(err)
	}
	metadata.SourceNode = "attacker"
	if _, err := encodeProcessFSOpenMetadata(metadata); err == nil {
		t.Fatal("partial caller provenance was accepted")
	}
}
