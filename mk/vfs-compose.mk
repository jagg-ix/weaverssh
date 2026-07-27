.PHONY: vfs-compose-focused-test vfs-compose-race-test test-vfs-compose-static vfs-encryption-focused-test vfs-encryption-race-test test-vfs-encryption-static luks-volume-focused-test luks-volume-race-test test-luks-volume-static

vfs-compose-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./vfscompose ./vfscrypt ./luksruntime ./filebackend ./internal/app ./internal/p9svc ./sessionfsops ./cmd/wv

vfs-compose-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./vfscompose ./vfscrypt ./luksruntime ./filebackend ./internal/app

test-vfs-compose-static:
	python3 -m pytest -q tests/test_vfs_compose.py tests/test_vfs_delegation.py tests/test_vfs_encryption.py tests/test_luks_volume.py tests/test_luks_live_guard.py

vfs-encryption-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./vfscrypt ./vfscompose ./luksruntime ./internal/app ./cmd/wv

vfs-encryption-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./vfscrypt

test-vfs-encryption-static:
	python3 -m pytest -q tests/test_vfs_encryption.py

luks-volume-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./luksruntime ./internal/app ./cmd/wv

luks-volume-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./luksruntime

test-luks-volume-static:
	python3 -m pytest -q tests/test_luks_volume.py tests/test_luks_live_guard.py
