.PHONY: api-contract-validate api-contract-lock api-contract-focused-test api-contract-race-test test-api-contract-static

API_CONTRACT_CATALOG ?= api/contracts/catalog.json
API_CONTRACT_LOCK ?= build/api/contracts.lock.json

api-contract-validate:
	GOTOOLCHAIN=local go run ./cmd/wv api-contract validate --catalog $(API_CONTRACT_CATALOG)

api-contract-lock:
	@mkdir -p $(dir $(API_CONTRACT_LOCK))
	@rm -f $(API_CONTRACT_LOCK)
	GOTOOLCHAIN=local go run ./cmd/wv api-contract lock --catalog $(API_CONTRACT_CATALOG) --output $(API_CONTRACT_LOCK)

api-contract-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./apicontract ./sessionapi ./cmd/wv

api-contract-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./apicontract ./sessionapi

test-api-contract-static:
	python3 -m pytest -q tests/test_api_contract.py
