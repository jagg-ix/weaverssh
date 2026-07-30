package evidencebinding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/codenotary/immudb/embedded/store"
)

const EmbeddedImmuDBProviderName = "embedded-immudb"

const embeddedImmuDBProofDomain = "weaverssh:evidence:embedded-immudb:v1\x00"

// EmbeddedImmuDBAnchor stores evidence heads in an immudb key-value store that
// runs in the same process as the WeaverSSH agent. It is useful when an agent
// must retain tamper-evident local evidence without depending on a separate
// immudb server.
//
// The embedded store is a local trust domain. It can participate in an anchor
// threshold, but it is not an independent witness when it shares the same host,
// filesystem, and administrative authority as the agent that produced the log.
type EmbeddedImmuDBAnchor struct {
	mu     sync.RWMutex
	path   string
	store  *store.ImmuStore
	closed bool
}

// OpenEmbeddedImmuDBAnchor creates or opens an embedded immudb store. The
// directory is owner-only and symbolic-link store roots are rejected.
func OpenEmbeddedImmuDBAnchor(path string) (*EmbeddedImmuDBAnchor, error) {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if cleaned == "" || cleaned == "." {
		return nil, fmt.Errorf("%w: embedded immudb path is required", ErrInvalidAnchor)
	}
	absolute, err := filepath.Abs(cleaned)
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(absolute); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: embedded immudb root must not be a symbolic link", ErrInvalidAnchor)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%w: embedded immudb root is not a directory", ErrInvalidAnchor)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(absolute, 0o700); err != nil {
		return nil, err
	}
	st, err := store.Open(absolute, store.DefaultOptions())
	if err != nil {
		return nil, fmt.Errorf("open embedded immudb store: %w", err)
	}
	return &EmbeddedImmuDBAnchor{path: absolute, store: st}, nil
}

func (p *EmbeddedImmuDBAnchor) Name() string { return EmbeddedImmuDBProviderName }

func (p *EmbeddedImmuDBAnchor) Path() string {
	if p == nil {
		return ""
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.path
}

func (p *EmbeddedImmuDBAnchor) Anchor(ctx context.Context, head Head) (AnchorReceipt, error) {
	if p == nil {
		return AnchorReceipt{}, fmt.Errorf("%w: embedded immudb provider is nil", ErrInvalidAnchor)
	}
	ctx = embeddedContext(ctx)
	statement, err := NewAnchorStatement(head)
	if err != nil {
		return AnchorReceipt{}, err
	}
	canonical, err := statement.CanonicalBytes()
	if err != nil {
		return AnchorReceipt{}, err
	}
	if err := contextErr(ctx); err != nil {
		return AnchorReceipt{}, err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || p.store == nil {
		return AnchorReceipt{}, fmt.Errorf("%w: embedded immudb store is closed", ErrInvalidAnchor)
	}
	key := embeddedImmuDBAnchorKey(statement)
	if valueRef, getErr := p.store.Get(ctx, key); getErr == nil {
		return embeddedImmuDBReceipt(p.Name(), statement, canonical, valueRef)
	} else if !errors.Is(getErr, store.ErrKeyNotFound) {
		return AnchorReceipt{}, getErr
	}

	tx, err := p.store.NewTx(ctx, &store.TxOptions{Mode: store.ReadWriteTx})
	if err != nil {
		return AnchorReceipt{}, err
	}
	defer tx.Cancel()
	if err := tx.Set(key, nil, canonical); err != nil {
		return AnchorReceipt{}, err
	}
	if _, err := tx.Commit(ctx); err != nil {
		return AnchorReceipt{}, err
	}
	valueRef, err := p.store.Get(ctx, key)
	if err != nil {
		return AnchorReceipt{}, err
	}
	return embeddedImmuDBReceipt(p.Name(), statement, canonical, valueRef)
}

func (p *EmbeddedImmuDBAnchor) Verify(ctx context.Context, head Head, receipt AnchorReceipt) error {
	if p == nil {
		return fmt.Errorf("%w: embedded immudb provider is nil", ErrInvalidAnchor)
	}
	ctx = embeddedContext(ctx)
	if err := receipt.ValidateFor(p.Name(), head); err != nil {
		return err
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	txID, historyCount, err := parseEmbeddedImmuDBExternalID(receipt.ExternalID)
	if err != nil {
		return err
	}
	if receipt.BlockNumber != txID {
		return ErrAnchorMismatch
	}
	canonical, err := receipt.Statement.CanonicalBytes()
	if err != nil {
		return err
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed || p.store == nil {
		return fmt.Errorf("%w: embedded immudb store is closed", ErrInvalidAnchor)
	}
	valueRef, err := p.store.Get(ctx, embeddedImmuDBAnchorKey(receipt.Statement))
	if err != nil {
		return err
	}
	value, err := valueRef.Resolve()
	if err != nil {
		return err
	}
	if !bytes.Equal(value, canonical) || valueRef.Tx() != txID || valueRef.HC() != historyCount {
		return ErrAnchorMismatch
	}
	if receipt.ProofSHA256 != embeddedImmuDBProof(canonical, txID, historyCount) {
		return ErrAnchorMismatch
	}
	return contextErr(ctx)
}

func (p *EmbeddedImmuDBAnchor) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.store == nil {
		return nil
	}
	err := p.store.Close()
	p.store = nil
	return err
}

func embeddedImmuDBReceipt(provider string, statement AnchorStatement, canonical []byte, valueRef store.ValueRef) (AnchorReceipt, error) {
	value, err := valueRef.Resolve()
	if err != nil {
		return AnchorReceipt{}, err
	}
	if !bytes.Equal(value, canonical) {
		return AnchorReceipt{}, ErrAnchorMismatch
	}
	txID := valueRef.Tx()
	historyCount := valueRef.HC()
	if txID == 0 || historyCount == 0 {
		return AnchorReceipt{}, fmt.Errorf("%w: embedded immudb returned invalid transaction metadata", ErrInvalidAnchor)
	}
	return AnchorReceipt{
		Version: AnchorVersion,
		Provider: provider,
		Statement: statement,
		ExternalID: fmt.Sprintf("tx:%d:hc:%d", txID, historyCount),
		ProofSHA256: embeddedImmuDBProof(canonical, txID, historyCount),
		Committed: true,
		BlockNumber: txID,
	}, nil
}

func embeddedImmuDBAnchorKey(statement AnchorStatement) []byte {
	return []byte(fmt.Sprintf("weaverssh:evidence:%s:%020d", statement.StreamID, statement.Sequence))
}

func embeddedImmuDBProof(canonical []byte, txID, historyCount uint64) string {
	buffer := make([]byte, 0, len(embeddedImmuDBProofDomain)+16+len(canonical))
	buffer = append(buffer, embeddedImmuDBProofDomain...)
	var numeric [16]byte
	binary.BigEndian.PutUint64(numeric[:8], txID)
	binary.BigEndian.PutUint64(numeric[8:], historyCount)
	buffer = append(buffer, numeric[:]...)
	buffer = append(buffer, canonical...)
	sum := sha256.Sum256(buffer)
	return hex.EncodeToString(sum[:])
}

func parseEmbeddedImmuDBExternalID(value string) (uint64, uint64, error) {
	parts := strings.Split(strings.TrimSpace(value), ":")
	if len(parts) != 4 || parts[0] != "tx" || parts[2] != "hc" {
		return 0, 0, ErrInvalidAnchor
	}
	txID, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || txID == 0 {
		return 0, 0, ErrInvalidAnchor
	}
	historyCount, err := strconv.ParseUint(parts[3], 10, 64)
	if err != nil || historyCount == 0 {
		return 0, 0, ErrInvalidAnchor
	}
	return txID, historyCount, nil
}

func embeddedContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
