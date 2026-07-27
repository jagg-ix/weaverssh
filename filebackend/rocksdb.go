package filebackend

import "errors"

var ErrRocksDBUnavailable = errors.New("filebackend: RocksDB support requires CGO and the rocksdb build tag")
