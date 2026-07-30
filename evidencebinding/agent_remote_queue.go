package evidencebinding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const AgentRemoteQueueVersion = "weaverssh.agent-remote-anchor-queue.v1"

type AgentRemoteDelivery struct {
	Version         string          `json:"version"`
	Head            Head            `json:"head"`
	Receipts        []AnchorReceipt `json:"receipts,omitempty"`
	Attempts        int             `json:"attempts"`
	LastAttemptUnix int64           `json:"last_attempt_unix,omitempty"`
	NextAttemptUnix int64           `json:"next_attempt_unix,omitempty"`
	DeliveredAtUnix int64           `json:"delivered_at_unix,omitempty"`
	LastError       string          `json:"last_error,omitempty"`
}

type AgentRemoteQueueStatus struct {
	Version           string `json:"version"`
	Enabled           bool   `json:"enabled"`
	Pending           int    `json:"pending"`
	Delivered         int    `json:"delivered"`
	TotalAttempts     int    `json:"total_attempts"`
	OldestPendingUnix int64  `json:"oldest_pending_unix,omitempty"`
	NextAttemptUnix   int64  `json:"next_attempt_unix,omitempty"`
	LastError         string `json:"last_error,omitempty"`
	LastDeliveredHead *Head  `json:"last_delivered_head,omitempty"`
}

type AgentRemoteQueueExport struct {
	Version string                `json:"version"`
	Status  AgentRemoteQueueStatus `json:"status"`
	Items   []AgentRemoteDelivery `json:"items"`
}

type AgentRemoteFlushReport struct {
	Version   string                 `json:"version"`
	Attempted int                    `json:"attempted"`
	Delivered int                    `json:"delivered"`
	Failures  map[string]string      `json:"failures,omitempty"`
	Status    AgentRemoteQueueStatus `json:"status"`
}

type AgentRemoteQueueConfig struct {
	Path       string
	MinBackoff time.Duration
	MaxBackoff time.Duration
	PollEvery  time.Duration
}

type agentRemoteQueueState struct {
	Version string                `json:"version"`
	Items   []AgentRemoteDelivery `json:"items"`
}

// AgentRemoteAnchorQueue durably retains heads until a configured N-of-M
// provider policy verifies enough remote receipts. Providers are expected to be
// idempotent because retries may repeat an already committed anchor request.
type AgentRemoteAnchorQueue struct {
	mu        sync.Mutex
	flushMu   sync.Mutex
	config    AgentRemoteQueueConfig
	providers []AnchorProvider
	policy    AnchorThresholdPolicy
	items     []AgentRemoteDelivery
	wake      chan struct{}
	cancel    context.CancelFunc
	done      chan struct{}
	closed    bool
}

func OpenAgentRemoteAnchorQueue(parent context.Context, config AgentRemoteQueueConfig, providers []AnchorProvider, policy AnchorThresholdPolicy) (*AgentRemoteAnchorQueue, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("%w: remote providers are required", ErrInvalidAnchor)
	}
	path := strings.TrimSpace(config.Path)
	if path == "" {
		return nil, fmt.Errorf("%w: remote queue path is required", ErrInvalidAnchor)
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if err := ensureOwnerDirectory(filepath.Dir(absolute)); err != nil {
		return nil, err
	}
	if err := rejectSymlink(absolute); err != nil {
		return nil, err
	}
	config.Path = absolute
	if config.MinBackoff <= 0 {
		config.MinBackoff = 5 * time.Second
	}
	if config.MaxBackoff < config.MinBackoff {
		config.MaxBackoff = 5 * time.Minute
	}
	if config.PollEvery <= 0 {
		config.PollEvery = time.Second
	}
	queue := &AgentRemoteAnchorQueue{
		config: config, providers: append([]AnchorProvider(nil), providers...), policy: policy,
		wake: make(chan struct{}, 1), done: make(chan struct{}),
	}
	if err := queue.load(); err != nil {
		_ = CloseAnchorProviders(providers)
		return nil, err
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	queue.cancel = cancel
	go queue.run(ctx)
	return queue, nil
}

func (q *AgentRemoteAnchorQueue) Enqueue(head Head) error {
	if q == nil {
		return ErrInvalidAnchor
	}
	if _, err := NewAnchorStatement(head); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return fmt.Errorf("%w: remote queue is closed", ErrInvalidAnchor)
	}
	for _, item := range q.items {
		if item.Head == head {
			return nil
		}
	}
	q.items = append(q.items, AgentRemoteDelivery{Version: AgentRemoteQueueVersion, Head: head, NextAttemptUnix: time.Now().UTC().Unix()})
	if err := q.persistLocked(); err != nil {
		q.items = q.items[:len(q.items)-1]
		return err
	}
	q.signal()
	return nil
}

// Flush attempts every due item. force ignores NextAttemptUnix. Provider
// failures are reported in the returned value while persistence and context
// failures are returned as errors.
func (q *AgentRemoteAnchorQueue) Flush(ctx context.Context, force bool) (AgentRemoteFlushReport, error) {
	if q == nil {
		return AgentRemoteFlushReport{}, ErrInvalidAnchor
	}
	if ctx == nil {
		ctx = context.Background()
	}
	q.flushMu.Lock()
	defer q.flushMu.Unlock()
	report := AgentRemoteFlushReport{Version: AgentRemoteQueueVersion, Failures: map[string]string{}}

	for {
		index, item, ok := q.nextDue(force, time.Now().UTC())
		if !ok {
			break
		}
		if err := ctx.Err(); err != nil {
			return report, err
		}
		report.Attempted++
		receipts, anchorErr := q.policy.Anchor(ctx, item.Head)
		q.mu.Lock()
		if index >= len(q.items) || q.items[index].Head != item.Head {
			q.mu.Unlock()
			continue
		}
		current := &q.items[index]
		current.Attempts++
		current.LastAttemptUnix = time.Now().UTC().Unix()
		current.Receipts = mergeAnchorReceipts(current.Receipts, receipts)
		_, verifyErr := q.policy.Verify(ctx, current.Head, current.Receipts)
		if verifyErr == nil {
			current.DeliveredAtUnix = time.Now().UTC().Unix()
			current.NextAttemptUnix = 0
			current.LastError = ""
			report.Delivered++
		} else {
			combined := errors.Join(anchorErr, verifyErr)
			current.LastError = combined.Error()
			current.NextAttemptUnix = time.Now().UTC().Add(q.backoff(current.Attempts)).Unix()
			report.Failures[remoteHeadKey(current.Head)] = current.LastError
		}
		persistErr := q.persistLocked()
		q.mu.Unlock()
		if persistErr != nil {
			return report, persistErr
		}
	}
	if len(report.Failures) == 0 {
		report.Failures = nil
	}
	report.Status = q.Status()
	return report, nil
}

func (q *AgentRemoteAnchorQueue) Status() AgentRemoteQueueStatus {
	status := AgentRemoteQueueStatus{Version: AgentRemoteQueueVersion, Enabled: q != nil}
	if q == nil {
		return status
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, item := range q.items {
		status.TotalAttempts += item.Attempts
		if item.DeliveredAtUnix > 0 {
			status.Delivered++
			head := item.Head
			status.LastDeliveredHead = &head
			continue
		}
		status.Pending++
		if status.OldestPendingUnix == 0 || item.Head.Sequence < uint64(status.OldestPendingUnix) {
			status.OldestPendingUnix = item.LastAttemptUnix
			if status.OldestPendingUnix == 0 {
				status.OldestPendingUnix = item.NextAttemptUnix
			}
		}
		if item.NextAttemptUnix > 0 && (status.NextAttemptUnix == 0 || item.NextAttemptUnix < status.NextAttemptUnix) {
			status.NextAttemptUnix = item.NextAttemptUnix
		}
		if item.LastError != "" {
			status.LastError = item.LastError
		}
	}
	return status
}

func (q *AgentRemoteAnchorQueue) Export() AgentRemoteQueueExport {
	if q == nil {
		return AgentRemoteQueueExport{Version: AgentRemoteQueueVersion, Status: AgentRemoteQueueStatus{Version: AgentRemoteQueueVersion}}
	}
	q.mu.Lock()
	items := make([]AgentRemoteDelivery, len(q.items))
	for i, item := range q.items {
		items[i] = cloneRemoteDelivery(item)
	}
	q.mu.Unlock()
	return AgentRemoteQueueExport{Version: AgentRemoteQueueVersion, Status: q.Status(), Items: items}
}

func (q *AgentRemoteAnchorQueue) Close() error {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return nil
	}
	q.closed = true
	cancel := q.cancel
	q.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	<-q.done
	return CloseAnchorProviders(q.providers)
}

func (q *AgentRemoteAnchorQueue) run(ctx context.Context) {
	defer close(q.done)
	ticker := time.NewTicker(q.config.PollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _ = q.Flush(ctx, false)
		case <-q.wake:
			_, _ = q.Flush(ctx, false)
		}
	}
}

func (q *AgentRemoteAnchorQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *AgentRemoteAnchorQueue) nextDue(force bool, now time.Time) (int, AgentRemoteDelivery, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return 0, AgentRemoteDelivery{}, false
	}
	for index, item := range q.items {
		if item.DeliveredAtUnix > 0 {
			continue
		}
		if force || item.NextAttemptUnix == 0 || item.NextAttemptUnix <= now.Unix() {
			return index, cloneRemoteDelivery(item), true
		}
	}
	return 0, AgentRemoteDelivery{}, false
}

func (q *AgentRemoteAnchorQueue) backoff(attempt int) time.Duration {
	backoff := q.config.MinBackoff
	for i := 1; i < attempt && backoff < q.config.MaxBackoff; i++ {
		if backoff > q.config.MaxBackoff/2 {
			return q.config.MaxBackoff
		}
		backoff *= 2
	}
	if backoff > q.config.MaxBackoff {
		return q.config.MaxBackoff
	}
	return backoff
}

func (q *AgentRemoteAnchorQueue) load() error {
	data, err := os.ReadFile(q.config.Path)
	if errors.Is(err, os.ErrNotExist) {
		return q.persistState(agentRemoteQueueState{Version: AgentRemoteQueueVersion})
	}
	if err != nil {
		return err
	}
	var state agentRemoteQueueState
	if err := decodeStrictJSON(data, &state); err != nil {
		return err
	}
	if state.Version != AgentRemoteQueueVersion {
		return fmt.Errorf("%w: remote queue version", ErrInvalidAnchor)
	}
	seen := map[string]struct{}{}
	for index, item := range state.Items {
		if item.Version != AgentRemoteQueueVersion {
			return fmt.Errorf("%w: remote queue item %d", ErrInvalidAnchor, index)
		}
		if _, err := NewAnchorStatement(item.Head); err != nil {
			return err
		}
		key := remoteHeadKey(item.Head)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("%w: duplicate remote head %s", ErrInvalidAnchor, key)
		}
		seen[key] = struct{}{}
		if item.DeliveredAtUnix > 0 {
			if _, err := q.policy.Verify(context.Background(), item.Head, item.Receipts); err != nil {
				return fmt.Errorf("verify delivered remote head %s: %w", key, err)
			}
		}
	}
	q.items = state.Items
	return nil
}

func (q *AgentRemoteAnchorQueue) persistLocked() error {
	items := make([]AgentRemoteDelivery, len(q.items))
	for i, item := range q.items {
		items[i] = cloneRemoteDelivery(item)
	}
	return q.persistState(agentRemoteQueueState{Version: AgentRemoteQueueVersion, Items: items})
}

func (q *AgentRemoteAnchorQueue) persistState(state agentRemoteQueueState) error {
	payload, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	temporary := q.config.Path + ".tmp"
	if err := rejectSymlink(temporary); err != nil {
		return err
	}
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_ = os.Chmod(temporary, 0o600)
	if err := os.Rename(temporary, q.config.Path); err != nil {
		if removeErr := os.Remove(q.config.Path); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			return err
		}
		if retryErr := os.Rename(temporary, q.config.Path); retryErr != nil {
			return retryErr
		}
	}
	return os.Chmod(q.config.Path, 0o600)
}

func mergeAnchorReceipts(existing, incoming []AnchorReceipt) []AnchorReceipt {
	byProvider := make(map[string]AnchorReceipt, len(existing)+len(incoming))
	for _, receipt := range existing {
		byProvider[receipt.Provider] = receipt
	}
	for _, receipt := range incoming {
		byProvider[receipt.Provider] = receipt
	}
	names := make([]string, 0, len(byProvider))
	for name := range byProvider {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]AnchorReceipt, 0, len(names))
	for _, name := range names {
		out = append(out, byProvider[name])
	}
	return out
}

func remoteHeadKey(head Head) string {
	return fmt.Sprintf("%s:%020d:%s", head.StreamID, head.Sequence, head.StatementSHA256)
}

func cloneRemoteDelivery(item AgentRemoteDelivery) AgentRemoteDelivery {
	payload, _ := json.Marshal(item)
	var cloned AgentRemoteDelivery
	_ = json.Unmarshal(payload, &cloned)
	return cloned
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrInvalidAnchor
	}
	return nil
}
