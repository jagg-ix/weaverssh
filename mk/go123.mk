# Go 1.23.2 compatibility build and validation.
GO123_BUILD_TOOL ?= tools/verification/build_go123.sh
GO123_OUTPUT ?= build/bin/wv-go1.23.2

.PHONY: go123-build go123-build-exact go123-test

go123-build: ## Test transport packages and build wv with an installed Go 1.23 toolchain
	@GOTOOLCHAIN=local OUTPUT="$(GO123_OUTPUT)" sh "$(GO123_BUILD_TOOL)"

go123-build-exact: ## Require exact Go 1.23.2, test transport packages, and build wv
	@GOTOOLCHAIN=local GO123_REQUIRE_EXACT=1 OUTPUT="$(GO123_OUTPUT)" sh "$(GO123_BUILD_TOOL)"

go123-test: ## Require exact Go 1.23.2 and run the complete repository test suite before building
	@GOTOOLCHAIN=local GO123_REQUIRE_EXACT=1 GO123_FULL_TESTS=1 OUTPUT="$(GO123_OUTPUT)" sh "$(GO123_BUILD_TOOL)"
