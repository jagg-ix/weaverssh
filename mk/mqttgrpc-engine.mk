# MQTT/gRPC multi-listener engine validation.

.PHONY: mqttgrpc-engine-focused-test test-mqttgrpc-engine-static

mqttgrpc-engine-focused-test: ## Test route management, lifecycle control, and the command package
	@GOTOOLCHAIN=local go test -count=1 ./mqttgrpcengine ./socketcontrol ./cmd/wv

test-mqttgrpc-engine-static: ## Validate command, control, documentation, and example surfaces
	@PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -p no:cacheprovider tests/test_mqttgrpc_engine_completion.py
