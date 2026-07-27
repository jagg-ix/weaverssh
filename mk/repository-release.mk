# Native repository publication, deterministic release bundles, and transactional updates.
NATIVE_REPOSITORY_TOOL ?= tools/packaging/build_native_repositories.py
RELEASE_BUNDLE_TOOL ?= tools/packaging/build_release_bundle.py
UPDATE_TOOL ?= tools/packaging/update_weaverssh.py
NATIVE_REPOSITORY_DIR ?= dist/native-repositories
RELEASE_BUNDLE_DIR ?= dist/release
REPOSITORY_SUITE ?= stable
REPOSITORY_COMPONENT ?= main
REPOSITORY_URL_BASE ?=
REPOSITORY_ARTIFACTS ?=
REPOSITORY_CHANNELS ?=
RELEASE_ARTIFACTS ?=
RELEASE_URL_BASE ?=
RELEASE_SIGN_METHOD ?= none
RELEASE_SIGN_KEY ?=
UPDATE_ARTIFACT ?=
UPDATE_CHECKSUM ?=
UPDATE_MANAGER ?= auto
UPDATE_RPM_FAMILY ?= redhat
UPDATE_CURRENT_BINARY ?=
UPDATE_ROLLBACK_ARTIFACT ?=
UPDATE_ROLLBACK_CHECKSUM ?=

REPOSITORY_ARTIFACT_ARGS = $(foreach artifact,$(REPOSITORY_ARTIFACTS),--artifact $(artifact))
REPOSITORY_CHANNEL_ARGS = $(foreach channel,$(REPOSITORY_CHANNELS),--channel $(channel))
RELEASE_ARTIFACT_ARGS = $(foreach artifact,$(RELEASE_ARTIFACTS),--artifact $(artifact))
UPDATE_CHECKSUM_ARG = $(if $(strip $(UPDATE_CHECKSUM)),--checksum $(UPDATE_CHECKSUM),)
UPDATE_CURRENT_ARG = $(if $(strip $(UPDATE_CURRENT_BINARY)),--current-binary $(UPDATE_CURRENT_BINARY),)
UPDATE_ROLLBACK_ARG = $(if $(strip $(UPDATE_ROLLBACK_ARTIFACT)),--rollback-artifact $(UPDATE_ROLLBACK_ARTIFACT),)
UPDATE_ROLLBACK_CHECKSUM_ARG = $(if $(strip $(UPDATE_ROLLBACK_CHECKSUM)),--rollback-checksum $(UPDATE_ROLLBACK_CHECKSUM),)
RELEASE_SIGN_KEY_ARG = $(if $(strip $(RELEASE_SIGN_KEY)),--sign-key $(RELEASE_SIGN_KEY),)
SOURCE_EPOCH_ARG = $(if $(strip $(SOURCE_DATE_EPOCH)),--source-date-epoch $(SOURCE_DATE_EPOCH),)

.PHONY: native-repositories-plan native-repositories native-repositories-native
.PHONY: release-bundle-plan release-bundle update-plan update-apply
.PHONY: test-repository-release

native-repositories-plan: ## Print APT/RPM/Arch/FreeBSD/Homebrew repository publication plan
	@test -n "$(REPOSITORY_ARTIFACTS)" || (echo "Set REPOSITORY_ARTIFACTS='<artifacts>'" >&2; exit 2)
	@$(PYTHON_BIN) $(NATIVE_REPOSITORY_TOOL) plan $(REPOSITORY_ARTIFACT_ARGS) $(REPOSITORY_CHANNEL_ARGS) --output-dir $(NATIVE_REPOSITORY_DIR) --suite $(REPOSITORY_SUITE) --component $(REPOSITORY_COMPONENT) --url-base "$(REPOSITORY_URL_BASE)" $(SOURCE_EPOCH_ARG)

native-repositories: ## Stage native package repositories without invoking native metadata tools
	@test -n "$(REPOSITORY_ARTIFACTS)" || (echo "Set REPOSITORY_ARTIFACTS='<artifacts>'" >&2; exit 2)
	@$(PYTHON_BIN) $(NATIVE_REPOSITORY_TOOL) build $(REPOSITORY_ARTIFACT_ARGS) $(REPOSITORY_CHANNEL_ARGS) --output-dir $(NATIVE_REPOSITORY_DIR) --suite $(REPOSITORY_SUITE) --component $(REPOSITORY_COMPONENT) --url-base "$(REPOSITORY_URL_BASE)" $(SOURCE_EPOCH_ARG) --replace

native-repositories-native: ## Stage repositories and invoke createrepo_c/repo-add/pkg when available
	@test -n "$(REPOSITORY_ARTIFACTS)" || (echo "Set REPOSITORY_ARTIFACTS='<artifacts>'" >&2; exit 2)
	@$(PYTHON_BIN) $(NATIVE_REPOSITORY_TOOL) build $(REPOSITORY_ARTIFACT_ARGS) $(REPOSITORY_CHANNEL_ARGS) --output-dir $(NATIVE_REPOSITORY_DIR) --suite $(REPOSITORY_SUITE) --component $(REPOSITORY_COMPONENT) --url-base "$(REPOSITORY_URL_BASE)" $(SOURCE_EPOCH_ARG) --execute-native --replace

release-bundle-plan: ## Print deterministic release bundle plan
	@test -n "$(RELEASE_ARTIFACTS)" || (echo "Set RELEASE_ARTIFACTS='<artifacts>'" >&2; exit 2)
	@$(PYTHON_BIN) $(RELEASE_BUNDLE_TOOL) plan --version $(PACKAGE_VERSION) --release $(PACKAGE_RELEASE) $(RELEASE_ARTIFACT_ARGS) --output-dir $(RELEASE_BUNDLE_DIR) --url-base "$(RELEASE_URL_BASE)" $(SOURCE_EPOCH_ARG) --sign-method $(RELEASE_SIGN_METHOD) $(RELEASE_SIGN_KEY_ARG)

release-bundle: ## Build deterministic release directory, tar.gz, zip, index, and checksums
	@test -n "$(RELEASE_ARTIFACTS)" || (echo "Set RELEASE_ARTIFACTS='<artifacts>'" >&2; exit 2)
	@$(PYTHON_BIN) $(RELEASE_BUNDLE_TOOL) build --version $(PACKAGE_VERSION) --release $(PACKAGE_RELEASE) $(RELEASE_ARTIFACT_ARGS) --output-dir $(RELEASE_BUNDLE_DIR) --url-base "$(RELEASE_URL_BASE)" $(SOURCE_EPOCH_ARG) --sign-method $(RELEASE_SIGN_METHOD) $(RELEASE_SIGN_KEY_ARG) --replace

update-plan: ## Print verified update, health-check, and rollback transaction plan
	@test -n "$(UPDATE_ARTIFACT)" || (echo "Set UPDATE_ARTIFACT=<package>" >&2; exit 2)
	@$(PYTHON_BIN) $(UPDATE_TOOL) plan $(UPDATE_ARTIFACT) $(UPDATE_CHECKSUM_ARG) --manager $(UPDATE_MANAGER) --rpm-family $(UPDATE_RPM_FAMILY) $(UPDATE_CURRENT_ARG) $(UPDATE_ROLLBACK_ARG) $(UPDATE_ROLLBACK_CHECKSUM_ARG)

update-apply: ## Execute verified update and automatic rollback; requires explicit UPDATE_ARTIFACT
	@test -n "$(UPDATE_ARTIFACT)" || (echo "Set UPDATE_ARTIFACT=<package>" >&2; exit 2)
	@$(PYTHON_BIN) $(UPDATE_TOOL) update $(UPDATE_ARTIFACT) $(UPDATE_CHECKSUM_ARG) --manager $(UPDATE_MANAGER) --rpm-family $(UPDATE_RPM_FAMILY) $(UPDATE_CURRENT_ARG) $(UPDATE_ROLLBACK_ARG) $(UPDATE_ROLLBACK_CHECKSUM_ARG) --execute

test-repository-release: ## Run native repository, release bundle, and update transaction tests
	@PYTHONDONTWRITEBYTECODE=1 $(PYTEST) -q -p no:cacheprovider tests/test_repository_release_infrastructure.py
