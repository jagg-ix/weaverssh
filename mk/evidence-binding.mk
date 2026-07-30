.PHONY: evidence-binding-focused-test evidence-binding-race-test test-evidence-binding-static \
	evidence-binding-immudb-live-test evidence-binding-fabric-live-test evidence-binding-live-test

evidence-binding-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./evidencebinding ./fabricbridge ./cmd/wv ./cmd/wv-evidence-anchor ./cmd/wv-fabric-anchor-bridge

evidence-binding-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./evidencebinding ./fabricbridge

test-evidence-binding-static:
	python3 tests/test_evidence_binding.py

evidence-binding-immudb-live-test:
	bash scripts/evidence/immudb-live-test.sh

evidence-binding-fabric-live-test:
	bash scripts/evidence/fabric-live-test.sh

evidence-binding-live-test: evidence-binding-immudb-live-test evidence-binding-fabric-live-test
