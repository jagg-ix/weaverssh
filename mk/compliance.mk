.PHONY: compliance-focused-test compliance-race-test test-compliance-static

compliance-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./compliance ./cmd/wv

compliance-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./compliance

test-compliance-static:
	python3 -m pytest -q tests/test_compliance_audit_screening.py
