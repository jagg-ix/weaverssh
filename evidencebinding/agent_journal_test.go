package evidencebinding

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestAgentEvidenceJournalPersistsAndVerifies(t *testing.T) {
	root := t.TempDir()
	anchor, err := OpenEmbeddedImmuDBAnchor(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	provider := NamedAnchorProvider{ProviderName: "node-a-local", Inner: anchor}
	journal, err := OpenAgentEvidenceJournal(context.Background(), AgentJournalConfig{Directory: filepath.Join(root, "journal"), StreamID: "agent/node-a"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	first, err := journal.Record(context.Background(), "runtime.started", "agent/node-a", map[string]string{"interface": "library"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := journal.Record(context.Background(), "connection.accepted", "agent/node-a", map[string]string{"network": "pipe"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Head.Sequence != 1 || second.Head.Sequence != 2 || second.Statement.Statement.PreviousSHA256 != first.Head.StatementSHA256 {
		t.Fatalf("unexpected journal chain: first=%+v second=%+v", first.Head, second.Head)
	}
	if report, err := journal.Verify(context.Background()); err != nil || !report.Authentic || !report.CompletenessBound {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}

	anchor, err = OpenEmbeddedImmuDBAnchor(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	provider = NamedAnchorProvider{ProviderName: "node-a-local", Inner: anchor}
	journal, err = OpenAgentEvidenceJournal(context.Background(), AgentJournalConfig{Directory: filepath.Join(root, "journal"), StreamID: "agent/node-a"}, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()
	defer provider.Close()
	status := journal.Status()
	if status.Records != 2 || status.Head == nil || status.Head.Sequence != 2 || status.LastEventKind != "connection.accepted" {
		t.Fatalf("status=%+v", status)
	}
	if len(journal.Export().Records) != 2 {
		t.Fatal("expected two exported records")
	}
}

func TestAgentEvidenceJournalRejectsLedgerTampering(t *testing.T) {
	root := t.TempDir()
	anchor, err := OpenEmbeddedImmuDBAnchor(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	provider := NamedAnchorProvider{ProviderName: "node-a-local", Inner: anchor}
	config := AgentJournalConfig{Directory: filepath.Join(root, "journal"), StreamID: "agent/node-a"}
	journal, err := OpenAgentEvidenceJournal(context.Background(), config, provider)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Record(context.Background(), "runtime.started", "agent/node-a", nil); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	ledger := filepath.Join(config.Directory, "agent-evidence.jsonl")
	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	for index := range data {
		if data[index] == 'r' {
			data[index] = 'x'
			break
		}
	}
	if err := os.WriteFile(ledger, data, 0o600); err != nil {
		t.Fatal(err)
	}
	anchor, err = OpenEmbeddedImmuDBAnchor(filepath.Join(root, "store"))
	if err != nil {
		t.Fatal(err)
	}
	provider = NamedAnchorProvider{ProviderName: "node-a-local", Inner: anchor}
	defer provider.Close()
	if _, err := OpenAgentEvidenceJournal(context.Background(), config, provider); err == nil {
		t.Fatal("tampered journal was accepted")
	}
}
