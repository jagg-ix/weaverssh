# Cross-platform source build and native package orchestration.
SOURCE_BUILD_PY ?= python3
SOURCE_BUILD_TOOL ?= tools/packaging/source_build.py
SOURCE_BUILD_PLATFORM ?= auto
SOURCE_BUILD_DISTRO ?=
SOURCE_BUILD_ARCH ?=
SOURCE_BUILD_SECURITY_PROFILE ?= $(SECURITY_PROFILE)
SOURCE_BUILD_VERSION ?= $(PACKAGE_VERSION)
SOURCE_BUILD_RELEASE ?= $(PACKAGE_RELEASE)
SOURCE_BUILD_ARGS = --platform $(SOURCE_BUILD_PLATFORM) --arch "$(SOURCE_BUILD_ARCH)" --version $(SOURCE_BUILD_VERSION) --release $(SOURCE_BUILD_RELEASE) --security-profile $(SOURCE_BUILD_SECURITY_PROFILE)
ifneq ($(strip $(SOURCE_BUILD_DISTRO)),)
SOURCE_BUILD_ARGS += --distro $(SOURCE_BUILD_DISTRO)
endif

.PHONY: source-build-plan source-build source-package source-release source-deps-plan
.PHONY: build-osx build-freebsd-native build-windows-native build-wsl build-vanilla-linux
.PHONY: package-macos package-freebsd package-windows package-wsl package-vanilla-linux
.PHONY: package-ubuntu package-debian package-redhat package-suse package-archlinux
.PHONY: test-cross-platform-build

source-build-plan: ## Detect host/distro and print source build plus package plan
	@$(SOURCE_BUILD_PY) $(SOURCE_BUILD_TOOL) plan $(SOURCE_BUILD_ARGS)

source-deps-plan: ## Print build dependency plan for the detected platform
	@$(SOURCE_BUILD_PY) $(SOURCE_BUILD_TOOL) plan $(SOURCE_BUILD_ARGS) | $(SOURCE_BUILD_PY) -c 'import json,sys; print(" ".join(json.load(sys.stdin)["dependency_plan_command"]))'

source-build: ## Build the native/selected target from source
	@$(SOURCE_BUILD_PY) $(SOURCE_BUILD_TOOL) build $(SOURCE_BUILD_ARGS) --execute

source-package: ## Package an existing selected-target build using its native package family
	@$(SOURCE_BUILD_PY) $(SOURCE_BUILD_TOOL) package $(SOURCE_BUILD_ARGS) --execute

source-release: ## Build from source and produce the selected native package
	@$(SOURCE_BUILD_PY) $(SOURCE_BUILD_TOOL) all $(SOURCE_BUILD_ARGS) --execute

build-osx: ## Cross-build Darwin/macOS for SOURCE_BUILD_ARCH (default host arch)
	@$(MAKE) --no-print-directory source-build SOURCE_BUILD_PLATFORM=darwin

build-freebsd-native: ## Cross-build FreeBSD for SOURCE_BUILD_ARCH (default host arch)
	@$(MAKE) --no-print-directory source-build SOURCE_BUILD_PLATFORM=freebsd

build-windows-native: ## Cross-build Windows for SOURCE_BUILD_ARCH (default host arch)
	@$(MAKE) --no-print-directory source-build SOURCE_BUILD_PLATFORM=windows

build-wsl: ## Build the Linux target explicitly as a WSL build
	@$(MAKE) --no-print-directory source-build SOURCE_BUILD_PLATFORM=wsl

build-vanilla-linux: ## Build a portable Linux binary for SOURCE_BUILD_ARCH
	@$(MAKE) --no-print-directory source-build SOURCE_BUILD_PLATFORM=linux SOURCE_BUILD_DISTRO=unknown

package-macos: ## Build Darwin and create a macOS pkg (pkgbuild required on macOS)
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=darwin

package-freebsd: ## Build FreeBSD and create a pkg-style archive
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=freebsd

package-windows: ## Build Windows and create a zip with PowerShell installer
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=windows

package-wsl: ## Build/package for the detected or selected WSL distribution
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=wsl

package-vanilla-linux: ## Build Linux and create portable tar.gz plus zip archives
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=linux SOURCE_BUILD_DISTRO=unknown

package-ubuntu: ## Build Linux and create an Ubuntu-compatible deb package
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=linux SOURCE_BUILD_DISTRO=ubuntu

package-debian: ## Build Linux and create a Debian-compatible deb package
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=linux SOURCE_BUILD_DISTRO=debian

package-redhat: ## Build Linux and create a Red Hat/Fedora/Rocky/Alma RPM
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=linux SOURCE_BUILD_DISTRO=rhel

package-suse: ## Build Linux and create an openSUSE/SLES RPM with SUSE dependencies
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=linux SOURCE_BUILD_DISTRO=opensuse

package-archlinux: ## Build Linux and create an Arch Linux pkg.tar.zst
	@$(MAKE) --no-print-directory source-release SOURCE_BUILD_PLATFORM=linux SOURCE_BUILD_DISTRO=arch

test-cross-platform-build: ## Run source-build and native-package planning tests
	@PYTHONDONTWRITEBYTECODE=1 $(PYTEST) -q -p no:cacheprovider tests/test_cross_platform_source_build.py
