# Real gRPC acceptance over the MQTT-framed stream adapter.
MQTTGRPC_E2E_DIR ?= tools/verification/go/mqttgrpc-e2e
MQTTGRPC_E2E_TIMEOUT ?= 90s

.PHONY: mqttgrpc-e2e mqttgrpc-e2e-download mqttgrpc-focused-test

mqttgrpc-e2e-download: ## Download the isolated real-gRPC acceptance module
	@cd "$(MQTTGRPC_E2E_DIR)" && GOTOOLCHAIN=local go mod download

mqttgrpc-e2e: ## Run unary and bidirectional streaming gRPC over MQTT frames
	@cd "$(MQTTGRPC_E2E_DIR)" && GOTOOLCHAIN=local go test -count=1 -timeout "$(MQTTGRPC_E2E_TIMEOUT)" ./...

mqttgrpc-focused-test: ## Test framing, unsigned/proof session bridges, TCP policy, and CLI integration
	@GOTOOLCHAIN=local go test -count=1 -timeout "$(MQTTGRPC_E2E_TIMEOUT)" \
		./mqttgrpc ./sessionmqttgrpc ./sessionmqttgrpcproof ./sessiontcp ./internal/app ./cmd/wv
