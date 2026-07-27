# Reproducible source archives, distro source recipes, and artifact verification.
SOURCE_DIST_TOOL ?= tools/packaging/build_source_distribution.py
SOURCE_RECIPES_TOOL ?= tools/packaging/build_source_recipes.py
ARTIFACT_VERIFY_TOOL ?= tools/packaging/verify_release_artifact.py
SOURCE_DIST_DIR ?= dist/source
SOURCE_RECIPES_DIR ?= dist/source-recipes
SOURCE_DIST_VENDOR ?= 1
SOURCE_DATE_EPOCH ?=
SOURCE_ARCHIVE ?= $(SOURCE_DIST_DIR)/weaverssh-$(PACKAGE_VERSION)-$(PACKAGE_RELEASE)-source.tar.gz
SOURCE_URL ?= file://$(abspath $(SOURCE_ARCHIVE))
SOURCE_SHA256 ?=
SOURCE_SIZE ?=
VERIFY_ARTIFACT ?=
VERIFY_CHECKSUM ?=
SOURCE_VENDOR_ARG = $(if $(filter 1 yes true,$(SOURCE_DIST_VENDOR)),--vendor,--no-vendor)
SOURCE_EPOCH_ARG = $(if $(strip $(SOURCE_DATE_EPOCH)),--source-date-epoch $(SOURCE_DATE_EPOCH),)
SOURCE_SHA_ARG = $(if $(strip $(SOURCE_SHA256)),--source-sha256 $(SOURCE_SHA256),--source-archive $(SOURCE_ARCHIVE))
SOURCE_SIZE_ARG = $(if $(strip $(SOURCE_SIZE)),--source-size $(SOURCE_SIZE),)
VERIFY_CHECKSUM_ARG = $(if $(strip $(VERIFY_CHECKSUM)),--checksum $(VERIFY_CHECKSUM),)

.PHONY: source-dist-plan source-dist source-recipes-plan source-recipes
.PHONY: verify-artifact artifact-install-plan test-source-release

source-dist-plan: ## Print reproducible source archive plan
	@$(PYTHON_BIN) $(SOURCE_DIST_TOOL) plan --version $(PACKAGE_VERSION) --release $(PACKAGE_RELEASE) --dist-dir $(SOURCE_DIST_DIR) $(SOURCE_VENDOR_ARG) $(SOURCE_EPOCH_ARG)

source-dist: ## Build reproducible tar.gz/zip source archives, manifest, checksums, and SPDX SBOM
	@$(PYTHON_BIN) $(SOURCE_DIST_TOOL) build --version $(PACKAGE_VERSION) --release $(PACKAGE_RELEASE) --dist-dir $(SOURCE_DIST_DIR) $(SOURCE_VENDOR_ARG) $(SOURCE_EPOCH_ARG)

source-recipes-plan: ## Print distro-maintainer source recipe plan for SOURCE_ARCHIVE/SOURCE_URL
	@$(PYTHON_BIN) $(SOURCE_RECIPES_TOOL) plan --version $(PACKAGE_VERSION) --release $(PACKAGE_RELEASE) --source-url $(SOURCE_URL) $(SOURCE_SHA_ARG) $(SOURCE_SIZE_ARG) $(SOURCE_EPOCH_ARG) --output-dir $(SOURCE_RECIPES_DIR)

source-recipes: ## Generate Debian, RPM, Arch, FreeBSD, and Homebrew source recipes
	@$(PYTHON_BIN) $(SOURCE_RECIPES_TOOL) build --version $(PACKAGE_VERSION) --release $(PACKAGE_RELEASE) --source-url $(SOURCE_URL) $(SOURCE_SHA_ARG) $(SOURCE_SIZE_ARG) $(SOURCE_EPOCH_ARG) --output-dir $(SOURCE_RECIPES_DIR)

artifact-install-plan: ## Print non-mutating install plan for VERIFY_ARTIFACT
	@test -n "$(VERIFY_ARTIFACT)" || (echo "Set VERIFY_ARTIFACT=<artifact>" >&2; exit 2)
	@$(PYTHON_BIN) $(ARTIFACT_VERIFY_TOOL) plan "$(VERIFY_ARTIFACT)" $(VERIFY_CHECKSUM_ARG)

verify-artifact: ## Verify checksum, archive safety, internal manifests, and native metadata when available
	@test -n "$(VERIFY_ARTIFACT)" || (echo "Set VERIFY_ARTIFACT=<artifact>" >&2; exit 2)
	@$(PYTHON_BIN) $(ARTIFACT_VERIFY_TOOL) verify "$(VERIFY_ARTIFACT)" $(VERIFY_CHECKSUM_ARG)

test-source-release: ## Run source distribution, source recipe, and artifact verification tests
	@PYTHONDONTWRITEBYTECODE=1 $(PYTEST) -q -p no:cacheprovider tests/test_source_release_infrastructure.py
