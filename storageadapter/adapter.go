// Package storageadapter defines the bounded storage contract shared by
// WeaverSSH components and optional database-engine providers.
package storageadapter

import (
	"context"
	"errors"
	"time"
)

const ConfigVersion = "weaverssh.storage.v1"

var (
	ErrNotFound         = errors.New("storageadapter: key not found")
	ErrConflict         = errors.New("storageadapter: compare-and-swap conflict")
	ErrReadOnly         = errors.New("storageadapter: store is read-only")
	ErrClosed           = errors.New("storageadapter: store is closed")
	ErrUnsupported      = errors.New("storageadapter: operation unsupported")
	ErrEngineUnavailable = errors.New("storageadapter: engine unavailable")
)

type Capabilities struct {
	Transactions   bool `json:"transactions"`
	AtomicBatch    bool `json:"atomic_batch"`
	CompareAndSwap bool `json:"compare_and_swap"`
	OrderedScan    bool `json:"ordered_scan"`
	Durable        bool `json:"durable"`
	ReadOnly       bool `json:"read_only"`
}

type Snapshot struct {
	Engine       string       `json:"engine"`
	Namespace    string       `json:"namespace,omitempty"`
	Capabilities Capabilities `json:"capabilities"`
	Entries      uint64       `json:"entries,omitempty"`
	Bytes        uint64       `json:"bytes,omitempty"`
	OpenedAt     time.Time    `json:"opened_at,omitempty"`
	LastError    string       `json:"last_error,omitempty"`
}

type Entry struct {
	Key   []byte `json:"key"`
	Value []byte `json:"value"`
}

type ScanOptions struct {
	Prefix []byte
	After  []byte
	Limit  int
}

type Tx interface {
	Get(key []byte) ([]byte, error)
	Put(key, value []byte) error
	Delete(key []byte) error
	CompareAndSwap(key, oldValue, newValue []byte) error
}

type Store interface {
	Name() string
	Capabilities() Capabilities
	Get(context.Context, []byte) ([]byte, error)
	Scan(context.Context, ScanOptions) ([]Entry, error)
	Update(context.Context, func(Tx) error) error
	Snapshot() Snapshot
	Close() error
}

type Factory func(context.Context, Config) (Store, error)
