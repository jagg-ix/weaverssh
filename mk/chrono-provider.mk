CHRONO_PROVIDER_DIR ?= tools/chrono-provider
CHRONO_PROVIDER_OUTPUT ?= build/bin/weaverssh-chrono-provider
CHRONO_PROVIDER_TOOLCHAIN ?= go1.26.1

.PHONY: chrono-provider-client-test chrono-provider-client-race-test chrono-provider-build chrono-provider-test chrono-provider-sqlite-build chrono-provider-rocksdb-build test-chrono-provider-static

chrono-provider-client-test:
	GOTOOLCHAIN=local go test -count=1 ./chronoprovider ./chronoselect ./socketcontrol ./cmd/wv ./internal/app

chrono-provider-client-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./chronoprovider ./chronoselect ./socketcontrol

chrono-provider-build:
	mkdir -p $$(dirname "$(CHRONO_PROVIDER_OUTPUT)")
	cd $(CHRONO_PROVIDER_DIR) && GOTOOLCHAIN=$(CHRONO_PROVIDER_TOOLCHAIN) go build -trimpath -buildvcs=false -o ../../$(CHRONO_PROVIDER_OUTPUT) .

chrono-provider-test:
	cd $(CHRONO_PROVIDER_DIR) && GOTOOLCHAIN=$(CHRONO_PROVIDER_TOOLCHAIN) go test -count=1 ./...

chrono-provider-sqlite-build:
	mkdir -p $$(dirname "$(CHRONO_PROVIDER_OUTPUT)-sqlite")
	cd $(CHRONO_PROVIDER_DIR) && CGO_ENABLED=1 GOTOOLCHAIN=$(CHRONO_PROVIDER_TOOLCHAIN) go build -tags sqlite -trimpath -buildvcs=false -o ../../$(CHRONO_PROVIDER_OUTPUT)-sqlite .

chrono-provider-rocksdb-build:
	mkdir -p $$(dirname "$(CHRONO_PROVIDER_OUTPUT)-rocksdb")
	cd $(CHRONO_PROVIDER_DIR) && CGO_ENABLED=1 GOTOOLCHAIN=$(CHRONO_PROVIDER_TOOLCHAIN) go build -tags rocksdb -trimpath -buildvcs=false -o ../../$(CHRONO_PROVIDER_OUTPUT)-rocksdb .

test-chrono-provider-static:
	python3 -m pytest -q tests/test_chrono_provider.py
