package evidencebinding

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAgentJournalSnapshotVerifiesAndRejectsMutation(t *testing.T) {
	anchor, err := OpenEmbeddedImmuDBAnchor(filepath.Join(t.TempDir(), "store"))
	if err != nil { t.Fatal(err) }
	defer anchor.Close()
	journal, err := OpenAgentEvidenceJournal(context.Background(), AgentJournalConfig{
		Directory: filepath.Join(t.TempDir(), "journal"), StreamID: "agent/snapshot-test",
	}, NamedAnchorProvider{ProviderName: "local", Inner: anchor})
	if err != nil { t.Fatal(err) }
	defer journal.Close()
	if _, err := journal.Record(context.Background(), "runtime.initialized", "agent/snapshot-test", map[string]string{"interface": "library"}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := journal.Snapshot()
	if err != nil { t.Fatal(err) }
	report, err := VerifyAgentJournalSnapshot(snapshot)
	if err != nil { t.Fatal(err) }
	if !report.Authentic || report.Head.Sequence != 1 { t.Fatalf("unexpected report: %+v", report) }

	mutated := snapshot
	mutated.Export.Records[0].Event.Kind = "runtime.modified"
	if _, err := VerifyAgentJournalSnapshot(mutated); err == nil {
		t.Fatal("mutated snapshot was accepted")
	}
}

func TestDecodeAgentJournalSnapshotRejectsTrailingJSON(t *testing.T) {
	if _, err := DecodeAgentJournalSnapshot([]byte(`{"version":"x"} {}`)); err == nil {
		t.Fatal("trailing JSON accepted")
	}
}
