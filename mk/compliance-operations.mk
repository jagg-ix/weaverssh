.PHONY: compliance-operations-focused-test compliance-operations-race-test test-compliance-operations-static

compliance-operations-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./compliance ./cmd/wv ./internal/app ./internal/vfscli

compliance-operations-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./compliance

test-compliance-operations-static:
	python3 -m pytest -q tests/test_compliance_operations_control.py
