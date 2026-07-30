package evidencebinding

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestEmbeddedImmuDBAnchorPersistsAcrossAgentRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-evidence")
	head := Head{StreamID: "agent/node-a", Sequence: 1, StatementSHA256: repeatSHA256('a')}

	provider, err := OpenEmbeddedImmuDBAnchor(path)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := provider.Anchor(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Provider != EmbeddedImmuDBProviderName || !receipt.Committed || receipt.BlockNumber == 0 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if err := provider.Verify(context.Background(), head, receipt); err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenEmbeddedImmuDBAnchor(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Verify(context.Background(), head, receipt); err != nil {
		t.Fatalf("persisted receipt failed after reopen: %v", err)
	}
	idempotent, err := reopened.Anchor(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if idempotent != receipt {
		t.Fatalf("idempotent anchor changed receipt\nfirst=%+v\nagain=%+v", receipt, idempotent)
	}
}

func TestEmbeddedImmuDBAnchorRejectsConflictingHeadAndTampering(t *testing.T) {
	provider, err := OpenEmbeddedImmuDBAnchor(filepath.Join(t.TempDir(), "agent-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	head := Head{StreamID: "agent/node-a", Sequence: 7, StatementSHA256: repeatSHA256('b')}
	receipt, err := provider.Anchor(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	conflicting := head
	conflicting.StatementSHA256 = repeatSHA256('c')
	if _, err := provider.Anchor(context.Background(), conflicting); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("conflicting head error=%v", err)
	}

	mutated := receipt
	mutated.ProofSHA256 = repeatSHA256('d')
	if err := provider.Verify(context.Background(), head, mutated); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("mutated proof error=%v", err)
	}
	mutated = receipt
	mutated.ExternalID = "tx:999:hc:1"
	if err := provider.Verify(context.Background(), head, mutated); !errors.Is(err, ErrAnchorMismatch) {
		t.Fatalf("mutated transaction error=%v", err)
	}
}

func TestEmbeddedImmuDBAnchorCloseAndContextCancellation(t *testing.T) {
	provider, err := OpenEmbeddedImmuDBAnchor(filepath.Join(t.TempDir(), "agent-evidence"))
	if err != nil {
		t.Fatal(err)
	}
	head := Head{StreamID: "agent/node-a", Sequence: 1, StatementSHA256: repeatSHA256('e')}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.Anchor(ctx, head); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled anchor error=%v", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Anchor(context.Background(), head); !errors.Is(err, ErrInvalidAnchor) {
		t.Fatalf("closed provider error=%v", err)
	}
}

func repeatSHA256(value byte) string {
	buffer := make([]byte, 64)
	for index := range buffer {
		buffer[index] = value
	}
	return string(buffer)
}
