package evidencebinding

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type queueTestProvider struct {
	mu   sync.Mutex
	name string
	fail bool
}

func (p *queueTestProvider) Name() string { return p.name }
func (p *queueTestProvider) setFail(value bool) { p.mu.Lock(); p.fail = value; p.mu.Unlock() }
func (p *queueTestProvider) Anchor(_ context.Context, head Head) (AnchorReceipt, error) {
	p.mu.Lock(); fail := p.fail; p.mu.Unlock()
	if fail { return AnchorReceipt{}, errors.New("provider unavailable") }
	statement, err := NewAnchorStatement(head)
	if err != nil { return AnchorReceipt{}, err }
	return AnchorReceipt{
		Version: AnchorVersion, Provider: p.name, Statement: statement,
		ExternalID: fmt.Sprintf("%s-%d", p.name, head.Sequence),
		ProofSHA256: strings.Repeat("a", 64), Committed: true,
	}, nil
}
func (p *queueTestProvider) Verify(_ context.Context, head Head, receipt AnchorReceipt) error {
	p.mu.Lock(); fail := p.fail; p.mu.Unlock()
	if fail { return errors.New("provider unavailable") }
	return receipt.ValidateFor(p.name, head)
}

func TestAgentRemoteQueuePersistsPartialReceiptsAndRecovers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "remote.json")
	first := &queueTestProvider{name: "first"}
	second := &queueTestProvider{name: "second", fail: true}
	providers := []AnchorProvider{first, second}
	policy, err := NewAnchorThresholdPolicy(providers, 2)
	if err != nil { t.Fatal(err) }
	queue, err := OpenAgentRemoteAnchorQueue(context.Background(), AgentRemoteQueueConfig{
		Path: path, MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond, PollEvery: time.Hour,
	}, providers, policy)
	if err != nil { t.Fatal(err) }
	head := Head{StreamID: "agent/test", Sequence: 1, StatementSHA256: strings.Repeat("b", 64)}
	if err := queue.Enqueue(head); err != nil { t.Fatal(err) }
	report, err := queue.Flush(context.Background(), true)
	if err != nil { t.Fatal(err) }
	if report.Status.Pending != 1 || len(queue.Export().Items[0].Receipts) != 1 {
		t.Fatalf("partial delivery not retained: %+v", report)
	}
	if err := queue.Close(); err != nil { t.Fatal(err) }

	second.setFail(false)
	policy, err = NewAnchorThresholdPolicy(providers, 2)
	if err != nil { t.Fatal(err) }
	queue, err = OpenAgentRemoteAnchorQueue(context.Background(), AgentRemoteQueueConfig{
		Path: path, MinBackoff: time.Millisecond, MaxBackoff: time.Millisecond, PollEvery: time.Hour,
	}, providers, policy)
	if err != nil { t.Fatal(err) }
	defer queue.Close()
	report, err = queue.Flush(context.Background(), true)
	if err != nil { t.Fatal(err) }
	if report.Status.Pending != 0 || report.Status.Delivered != 1 || len(queue.Export().Items[0].Receipts) != 2 {
		t.Fatalf("delivery did not recover after restart: %+v", report)
	}
}

func TestAgentRemoteQueueRejectsDuplicateHead(t *testing.T) {
	provider := &queueTestProvider{name: "only"}
	providers := []AnchorProvider{provider}
	policy, err := NewAnchorThresholdPolicy(providers, 1)
	if err != nil { t.Fatal(err) }
	queue, err := OpenAgentRemoteAnchorQueue(context.Background(), AgentRemoteQueueConfig{Path: filepath.Join(t.TempDir(), "remote.json"), PollEvery: time.Hour}, providers, policy)
	if err != nil { t.Fatal(err) }
	defer queue.Close()
	head := Head{StreamID: "agent/test", Sequence: 1, StatementSHA256: strings.Repeat("c", 64)}
	if err := queue.Enqueue(head); err != nil { t.Fatal(err) }
	if err := queue.Enqueue(head); err != nil { t.Fatal(err) }
	if got := len(queue.Export().Items); got != 1 { t.Fatalf("items=%d want=1", got) }
}
