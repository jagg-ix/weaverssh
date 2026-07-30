package evidencebinding

import (
	"context"
	"errors"
	"testing"
)

type fakeAnchorProvider struct {
	name      string
	anchorErr error
	verifyErr error
}

func (p fakeAnchorProvider) Name() string { return p.name }
func (p fakeAnchorProvider) Anchor(_ context.Context, head Head) (AnchorReceipt, error) {
	if p.anchorErr != nil {
		return AnchorReceipt{}, p.anchorErr
	}
	statement, _ := NewAnchorStatement(head)
	return AnchorReceipt{Version: AnchorVersion, Provider: p.name, Statement: statement, ExternalID: p.name + "-id", ProofSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Committed: true, BlockNumber: 1}, nil
}
func (p fakeAnchorProvider) Verify(_ context.Context, head Head, receipt AnchorReceipt) error {
	if p.verifyErr != nil {
		return p.verifyErr
	}
	return receipt.ValidateFor(p.name, head)
}

func TestAnchorThresholdAcceptsTwoIndependentProviders(t *testing.T) {
	policy, err := NewAnchorThresholdPolicy([]AnchorProvider{
		fakeAnchorProvider{name: "immudb"}, fakeAnchorProvider{name: "fabric"}, fakeAnchorProvider{name: "archive", anchorErr: ErrAnchorRejected},
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	head := anchorTestHead()
	receipts, err := policy.Anchor(context.Background(), head)
	if err != nil {
		t.Fatal(err)
	}
	if len(receipts) != 2 {
		t.Fatalf("receipts=%d", len(receipts))
	}
	report, err := policy.Verify(context.Background(), head, receipts)
	if err != nil || report.Valid != 2 {
		t.Fatalf("report=%+v err=%v", report, err)
	}
}

func TestAnchorThresholdRejectsDuplicatesUnknownsAndInsufficientQuorum(t *testing.T) {
	policy, _ := NewAnchorThresholdPolicy([]AnchorProvider{
		fakeAnchorProvider{name: "immudb"}, fakeAnchorProvider{name: "fabric", verifyErr: ErrAnchorMismatch},
	}, 2)
	head := anchorTestHead()
	statement, _ := NewAnchorStatement(head)
	immu := AnchorReceipt{Version: AnchorVersion, Provider: "immudb", Statement: statement, ExternalID: "i", ProofSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Committed: true}
	unknown := immu
	unknown.Provider = "unknown"
	report, err := policy.Verify(context.Background(), head, []AnchorReceipt{immu, immu, unknown})
	if !errors.Is(err, ErrAnchorThreshold) {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	if report.Valid != 1 {
		t.Fatalf("duplicate inflated quorum: %+v", report)
	}
	if report.Failures["immudb"] != "duplicate provider receipt" || report.Failures["unknown"] == "" {
		t.Fatalf("failures=%v", report.Failures)
	}
}

func TestAnchorThresholdConfigurationRejectsImpossibleOrDuplicatePolicy(t *testing.T) {
	provider := fakeAnchorProvider{name: "immudb"}
	if _, err := NewAnchorThresholdPolicy([]AnchorProvider{provider}, 2); !errors.Is(err, ErrAnchorThreshold) {
		t.Fatalf("threshold err=%v", err)
	}
	if _, err := NewAnchorThresholdPolicy([]AnchorProvider{provider, provider}, 1); !errors.Is(err, ErrInvalidAnchor) {
		t.Fatalf("duplicate err=%v", err)
	}
}
