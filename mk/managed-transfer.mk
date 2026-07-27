.PHONY: managed-transfer-focused-test managed-transfer-race-test test-managed-transfer-static

managed-transfer-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./archiveflow ./managedtransfer ./transferflow ./vfscompose ./cmd/wv ./cmd/wv-archive

managed-transfer-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./archiveflow ./managedtransfer ./transferflow ./vfscompose

test-managed-transfer-static:
	python3 -m pytest -q tests/test_managed_transfer.py tests/test_archive_flow.py tests/test_transfer_replay.py tests/test_replay_recovery.py
