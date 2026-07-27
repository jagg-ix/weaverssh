# Optional OPA Rego compatibility and policy-framework validation.
.PHONY: opa-rego-focused-test opa-rego-race-test test-opa-rego-static

opa-rego-focused-test: ## Test Rego client, hybrid rules, hooks, and stream authorization
	@GOTOOLCHAIN=local go test -count=1 ./regopolicy ./rules ./pubsub ./streampolicy

opa-rego-race-test: ## Run Rego compatibility packages with the Go race detector
	@GOTOOLCHAIN=local go test -race -count=1 ./regopolicy ./rules ./pubsub ./streampolicy

test-opa-rego-static: ## Check command, examples, launcher, and build-gate surfaces
	@PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider tests/test_opa_rego_compatibility.py
