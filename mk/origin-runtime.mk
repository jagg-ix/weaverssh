.PHONY: origin-runtime-validate-examples origin-runtime-focused-test origin-runtime-race-test test-origin-runtime-static

ORIGIN_RUNTIME_EXAMPLES := \
	docs/examples/origin-runtime/native.json \
	docs/examples/origin-runtime/wsl.json \
	docs/examples/origin-runtime/docker.json \
	docs/examples/origin-runtime/kubernetes-exec.json \
	docs/examples/origin-runtime/kubernetes-shared-storage.json \
	docs/examples/origin-runtime/kubernetes-hostpath.json \
	docs/examples/origin-runtime/vm-shared-folder.json

origin-runtime-validate-examples:
	@for config in $(ORIGIN_RUNTIME_EXAMPLES); do \
		GOTOOLCHAIN=local go run ./cmd/wv origin-runtime validate --config "$$config" || exit $$?; \
	done

origin-runtime-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./originruntime ./cmd/wv ./internal/app

origin-runtime-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./originruntime

test-origin-runtime-static:
	python3 -m pytest -q tests/test_origin_runtime.py
