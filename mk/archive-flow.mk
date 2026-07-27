ARCHIVE_BINARY?=wv-archive
ARCHIVE_PKG?=./cmd/wv-archive

COMMAND_PACKAGES += $(ARCHIVE_PKG)

.PHONY: build-archive archive-flow-focused-test archive-flow-race-test

build-archive: $(BIN_DIR)
	@echo "==> Building managed archive policy tool..."
	@$(GOBUILD) -o $(BIN_DIR)/$(ARCHIVE_BINARY) -v $(ARCHIVE_PKG)
	@echo "Build complete: $(BIN_DIR)/$(ARCHIVE_BINARY)"

build-all-binaries: build-archive
build-all-native-binaries: build-archive

archive-flow-focused-test:
	GOTOOLCHAIN=local go test -count=1 ./archiveflow ./managedtransfer ./cmd/wv-archive

archive-flow-race-test:
	GOTOOLCHAIN=local go test -race -count=1 ./archiveflow ./managedtransfer
