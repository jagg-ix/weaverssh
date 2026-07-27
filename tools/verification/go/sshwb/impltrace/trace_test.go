package impltrace

import (
	"path/filepath"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatalf("abs repo root: %v", err)
	}
	return root
}

func TestEmitAnchorsEveryRuntimeTraceEvent(t *testing.T) {
	records, err := Emit(repoRoot(t))
	if err != nil {
		t.Fatalf("Emit failed: %v", err)
	}
	if len(records) < 30 {
		t.Fatalf("expected canonical runtime trace, got %d events", len(records))
	}
	for i, rec := range records {
		if rec.Source != SourceName {
			t.Fatalf("record %d source=%q", i, rec.Source)
		}
		if rec.StepIndex != i {
			t.Fatalf("record %d step_index=%d", i, rec.StepIndex)
		}
		if rec.Implementation.File == "" || rec.Implementation.Symbol == "" || rec.Implementation.Line <= 0 {
			t.Fatalf("record %d missing implementation anchor: %+v", i, rec.Implementation)
		}
		if rec.TLA.Module == "" || rec.TLA.Action == "" {
			t.Fatalf("record %d missing TLA anchor: %+v", i, rec.TLA)
		}
	}
}
