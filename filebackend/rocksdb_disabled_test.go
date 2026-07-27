//go:build !rocksdb || !cgo

package filebackend

import (
	"errors"
	"testing"
)

func TestRocksDBRequiresBuildTagAndCGO(t *testing.T) {
	if _, err := OpenRocksDB(t.TempDir()); !errors.Is(err, ErrRocksDBUnavailable) {
		t.Fatalf("error=%v want ErrRocksDBUnavailable", err)
	}
}
