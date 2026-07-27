.PHONY: storage-adapter-focused-test storage-adapter-race-test storage-sqlite-test storage-rocksdb-test storage-sqlite-build storage-rocksdb-build test-storage-adapter-static

storage-adapter-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./storageadapter ./filebackend ./cmd/wv

storage-adapter-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./storageadapter ./filebackend

storage-sqlite-test:
	CGO_ENABLED=1 GOTOOLCHAIN=local go test -tags sqlite -count=1 ./storageadapter ./storageplugins/sqlite ./cmd/wv

storage-rocksdb-test:
	CGO_ENABLED=1 GOTOOLCHAIN=local go test -tags rocksdb -count=1 ./storageadapter ./storageplugins/rocksdb ./cmd/wv

storage-sqlite-build:
	CGO_ENABLED=1 GOTOOLCHAIN=local go build -tags sqlite -trimpath -buildvcs=false -o build/bin/wv-sqlite ./cmd/wv

storage-rocksdb-build:
	CGO_ENABLED=1 GOTOOLCHAIN=local go build -tags rocksdb -trimpath -buildvcs=false -o build/bin/wv-rocksdb ./cmd/wv

test-storage-adapter-static:
	python3 -m pytest -q tests/test_storage_adapter_infrastructure.py
