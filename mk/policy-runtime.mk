# Runtime policy enforcement checks.

.PHONY: policy-runtime-focused-test policy-runtime-race-test test-policy-runtime-static

policy-runtime-focused-test: ## Test runtime enforcement across transfers, events, and file backends
	@GOTOOLCHAIN=local go test -count=1 ./policyexec ./transferflow ./sessionevents ./filebackend ./internal/vfscli ./cmd/wv

policy-runtime-race-test: ## Race-test runtime policy and owned side-effect boundaries
	@GOTOOLCHAIN=local go test -race -count=1 ./policyexec ./transferflow ./sessionevents ./filebackend

test-policy-runtime-static: ## Validate command, examples, documentation, and build-gate surfaces
	@PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider tests/test_policy_runtime_enforcement.py
