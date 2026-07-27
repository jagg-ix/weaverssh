.PHONY: chrono-layer-focused-test chrono-layer-race-test test-chrono-layer-static chrono-ani03sha-test chrono-ani03sha-race-test

chrono-layer-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./chronolayer ./sessionchrono ./chronoipc ./chronopubsub ./internal/app ./cmd/wv

chrono-layer-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./chronolayer ./sessionchrono ./chronoipc ./chronopubsub ./internal/app

test-chrono-layer-static:
	python3 -m pytest -q tests/test_chrono_layer.py tests/test_chrono_time_normalization.py

chrono-ani03sha-test:
	cd integrations/ani03sha-chrono && GOTOOLCHAIN=local go test -count=1 ./...

chrono-ani03sha-race-test:
	cd integrations/ani03sha-chrono && GOTOOLCHAIN=local go test -race -count=1 ./...
