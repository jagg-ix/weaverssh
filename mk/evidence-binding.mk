.PHONY: evidence-binding-focused-test evidence-binding-race-test test-evidence-binding-static

evidence-binding-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./evidencebinding ./cmd/wv

evidence-binding-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./evidencebinding

test-evidence-binding-static:
	python3 tests/test_evidence_binding.py
