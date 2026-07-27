.PHONY: policy-admin-focused-test policy-admin-race-test test-policy-admin-static

policy-admin-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./policystore ./regopolicy ./policyexec ./cmd/wv

policy-admin-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./policystore ./regopolicy ./policyexec

test-policy-admin-static:
	python3 -m pytest -q tests/test_policy_admin_completion.py
