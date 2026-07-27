# Makefile for X11 WebSocket Server and Client

# Go parameters
GOCMD=go
GO_HARDENING_FLAGS?=-trimpath -buildvcs=false -ldflags="-s -w"
GOBUILD=$(GOCMD) build $(GO_HARDENING_FLAGS)
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOVET=$(GOCMD) vet
PYTHON_BIN?=python3
PYTEST?=$(PYTHON_BIN) -m pytest
JEPSEN_NODES?=203.0.113.10,203.0.113.20
JEPSEN_USER?=kb
JEPSEN_IDENTITY?=
JEPSEN_NEMESIS?=process-kill
JEPSEN_WORKLOAD?=x11-ws-handshake
JEPSEN_REMOTE_ROOT?=~/weaverssh-sut/current
JEPSEN_ANSIBLE_PLAYBOOK?=ansible/playbooks/install_wv.yml
JEPSEN_ANSIBLE_ARCHIVE?=$(ANSIBLE_WV_ARCHIVE)
JEPSEN_ANSIBLE_CHECKSUM?=$(ANSIBLE_WV_CHECKSUM)
JEPSEN_ANSIBLE_VERSION?=$(PACKAGE_VERSION)
JEPSEN_ANSIBLE_RELEASE?=$(PACKAGE_RELEASE)

# Binary names
MAIN_BINARY=wv
SERVER_BINARY=wv-server
CLIENT_BINARY=wv-client
AGENT_BINARY=wv-agent
SOCKS_BINARY=wv-socks
NINEP_BINARY=wv-9p
NATIVE_FORWARD_BINARY=wv-native-forward
# vfs:// namespace tools (single implementation, four entry points)
VFS_BINARIES=wcp wls wmkdir wtool
# FUSE mount (macFUSE / libfuse); native build only (not cross-compiled)
MOUNT_BINARY=wv-mount

# Package metadata
PACKAGE_VERSION?=0.1.0
PACKAGE_RELEASE?=1
PACKAGE_ARCH?=amd64
PACKAGE_BINARY_DIR?=$(LINUX_DIR)
PACKAGE_DIST_DIR?=./dist/packages
PACKAGE_PREFIX?=/usr
PACKAGE_FILE?=
DEPS_LOG?=$(HOME)/.weaverssh/logs/dependencies.jsonl
WV?=wv
BINARY_DIST_DIR?=./dist/binary
BINARY_DIST_TARGET?=
BINARY_DIST_SOURCE_DATE_EPOCH?=
BINARY_DIST_SIGN_KEY?=
BINARY_DIST_GPG_KEY?=
BINARY_DIST_SIGN?=
HOMEBREW_DIST_DIR?=./dist/homebrew
HOMEBREW_FORMULA_OUTPUT?=$(HOMEBREW_DIST_DIR)/Formula/weaverssh.rb
HOMEBREW_ARCHIVE?=
HOMEBREW_ARCHIVES?=$(HOMEBREW_ARCHIVE)
HOMEBREW_URL_BASE?=
HOMEBREW_LICENSE?=:cannot_represent
REPOSITORY_MANIFEST_DIST_DIR?=./dist/repository
REPOSITORY_MANIFEST_ARCHIVE?=
REPOSITORY_MANIFEST_ARCHIVES?=$(REPOSITORY_MANIFEST_ARCHIVE)
REPOSITORY_MANIFEST_CHANNELS?=
REPOSITORY_MANIFEST_URL_BASE?=
FREEBSD_PACKAGE_ARCH?=$(PACKAGE_ARCH)
FREEBSD_PACKAGE_BINARY_DIR?=$(BUILD_DIR)/freebsd-$(FREEBSD_PACKAGE_ARCH)
SNAP_DIST_DIR?=./dist/snap
SNAP_PROJECT_DIR?=$(SNAP_DIST_DIR)/weaverssh
SNAP_BINARY?=$(PACKAGE_BINARY_DIR)/wv
SNAP_ARCH?=$(PACKAGE_ARCH)
SNAP_BASE?=core24
SNAP_CONFINEMENT?=strict
SNAP_GRADE?=stable
SNAP_PLUG_ARGS?=
SNAPCRAFT?=snapcraft
PYTHON_DIST_DIR?=./dist/python
PYTHON_DIST_SOURCE_DATE_EPOCH?=
PYTHON_DIST_PROFILE?=core
PYTHON_DIST_SIGN_KEY?=
PYTHON_DIST_GPG_KEY?=
PYTHON_DIST_SIGN?=
PYTHON_DIST_DOWNLOAD_WHEELS?=
PYTHON_PIP_TARGET?=/tmp/weaverssh-pip-target
ANSIBLE_INVENTORY?=ansible/inventory.example.ini
ANSIBLE_SYNTAX_INVENTORY?=ansible/inventory.syntax.ini
ANSIBLE_PLAYBOOK?=ansible/playbooks/install_wv.yml
ANSIBLE_DOCKER_PLAYBOOK?=ansible/playbooks/install_wv_docker.yml
ANSIBLE_K8S_PLAYBOOK?=ansible/playbooks/install_wv_kubernetes.yml
ANSIBLE_DOCKER_CONTAINER?=
ANSIBLE_DOCKER_RUNTIME?=docker
ANSIBLE_K8S_NAMESPACE?=default
ANSIBLE_K8S_POD?=
ANSIBLE_K8S_CONTAINER?=
ANSIBLE_WV_ARCHIVE?=
ANSIBLE_WV_CHECKSUM?=
ANSIBLE_WV_VERSION?=$(PACKAGE_VERSION)
ANSIBLE_WV_RELEASE?=$(PACKAGE_RELEASE)
MAJOR_TARGET_PRESET?=major
LINUX_TARGET_PRESET?=linux-major
BUILD_TARGET?=
LINUX_PACKAGE_ARCHES?=amd64 arm64 armv7 386 ppc64le s390x riscv64
SECURITY_PROFILE?=hardened
CONTAINER_RUNTIME?=docker
NINEP_CONTAINER_IMAGE?=weaverssh/wv-9p:local
NINEP_CONTAINERFILE?=tools/containers/wv-9p.Containerfile
NINEP_CONTAINER_PLATFORM?=

# Command packages
MAIN_PKG=./cmd/wv
SERVER_PKG=./cmd/wv-server
CLIENT_PKG=./cmd/wv-client
AGENT_PKG=./cmd/wv-agent
SOCKS_PKG=./cmd/wv-socks
NINEP_PKG=./cmd/wv-9p
NATIVE_FORWARD_PKG=./cmd/wv-native-forward
VFS_PKGS=./cmd/wcp ./cmd/wls ./cmd/wmkdir ./cmd/wtool
MOUNT_PKG=./cmd/wv-mount

# Development package groups. Public library packages are importable by tools
# outside this module; internal packages are buildable only from this module.
COMMAND_PACKAGES=$(MAIN_PKG) $(SERVER_PKG) $(CLIENT_PKG) $(AGENT_PKG) $(SOCKS_PKG) $(NINEP_PKG) $(NATIVE_FORWARD_PKG) $(VFS_PKGS) $(MOUNT_PKG)
LIBRARY_PACKAGES?=./agentapi ./authproof ./display ./flowcontrol ./instrument ./padding ./pubsub ./relay ./rules ./tunnel
INTERNAL_LIBRARY_PACKAGES?=./internal/app ./internal/p9svc ./internal/p9client ./internal/vfs ./internal/vfscli ./internal/vfsmount

# Build directories
BUILD_DIR=./build
BIN_DIR=$(BUILD_DIR)/bin
LINUX_DIR=$(BUILD_DIR)/linux-x86_64
DARWIN_DIR=$(BUILD_DIR)/darwin-x86_64
DARWIN_ARM64_DIR=$(BUILD_DIR)/darwin-arm64
WINDOWS_DIR=$(BUILD_DIR)/windows-x86_64

# Default target
.DEFAULT_GOAL := build

# All phony targets
.PHONY: all build build-main build-server build-client build-client-native build-agent build-socks build-9p build-vfs build-mount build-native-forward build-9p-container build-9p-container-plan build-all-binaries build-all-native-binaries build-hardened
.PHONY: build-linux build-linux-arm64 build-darwin build-darwin-arm64 build-windows build-freebsd-amd64 build-freebsd-arm64 build-openbsd-amd64 build-openbsd-arm64 build-all
.PHONY: build-matrix-plan build-target build-major-architectures build-linux-major-architectures
.PHONY: list-libraries list-commands build-commands build-libraries build-internal-libraries build-library-surface dev-doctor dev-setup dev-fast dev-check fmt-check vet pytest-collect test-go test-go-race test-python-build test-authproof-agent-flags test-authproof-agent-integration
.PHONY: component-workflows-list component-workflows-check install-dev-plan deploy-local-plan verify-workflows-plan
.PHONY: jepsen-plan jepsen-unit jepsen-system-plan jepsen-system jepsen-ansible-install-plan jepsen-ansible-install-system
.PHONY: run-main run-hybrid run-server run-client
.PHONY: test verify-tunnel-policy clean deps fmt mod-verify init info help
.PHONY: package-plan package-tar package-zip package-deb package-rpm package-arch package-apk package-freebsd-pkg package-pkg package-portable package-linux package-bsd package-all binary-dist homebrew-formula-plan homebrew-formula package-brew-plan package-brew repository-manifests-plan repository-manifests package-nix-plan package-nix package-scoop-plan package-scoop package-chocolatey-plan package-chocolatey package-snap-plan package-snap-project package-snap python-dist python-dist-verify python-requirements-lock python-pip-check ansible-install-plan ansible-install-wv ansible-install-docker-plan ansible-install-docker ansible-install-k8s-plan ansible-install-k8s ansible-syntax-check
.PHONY: package-portable-linux-major-architectures
.PHONY: install-package-plan install-package
.PHONY: install-runtime-deps-plan install-runtime-deps-status install-runtime-deps install-runtime-deps-replace install-build-deps-plan install-build-deps-status install-build-deps install-build-deps-replace platform-setup-plan platform-setup-script linux-setup-plan linux-setup-script

all: deps build ## Install dependencies and build for current platform

help: ## Display this help message
	@echo "X11 WebSocket Server - Build System"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-20s %s\n", $$1, $$2}'

deps: ## Download and tidy Go dependencies
	@echo "==> Installing dependencies..."
	@$(GOMOD) download
	@$(GOMOD) tidy
	@echo "Dependencies installed"

# Build directories
$(BIN_DIR) $(LINUX_DIR) $(DARWIN_DIR) $(DARWIN_ARM64_DIR) $(WINDOWS_DIR):
	@mkdir -p $@

# Build for current platform (default - server native, client linux)
build: $(BIN_DIR) ## Build integrated server for current platform
	@echo "==> Building integrated server for current platform..."
	@$(GOBUILD) -o $(BIN_DIR)/$(MAIN_BINARY) -v $(MAIN_PKG)
	@echo "Build complete: $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

# Build main integrated server
build-main: $(BIN_DIR) ## Build integrated X11/WebSocket server
	@echo "==> Building integrated server..."
	@$(GOBUILD) -o $(BIN_DIR)/$(MAIN_BINARY) -v $(MAIN_PKG)
	@echo "Build complete: $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

# Build standalone server binary
build-server: $(BIN_DIR) ## Build standalone X11 server
	@echo "==> Building standalone X11 server..."
	@$(GOBUILD) -o $(BIN_DIR)/$(SERVER_BINARY) -v $(SERVER_PKG)
	@echo "Build complete: $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

# Build client binary for Linux x86_64 (default target platform)
build-client: $(LINUX_DIR) ## Build X11 test client for Linux x86_64 (default)
	@echo "==> Building X11 test client for Linux x86_64..."
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LINUX_DIR)/$(CLIENT_BINARY) $(CLIENT_PKG)
	@echo "Build complete: $(LINUX_DIR)/"
	@ls -lh $(LINUX_DIR)/

# Build client for native platform
build-client-native: $(BIN_DIR) ## Build X11 test client for native platform
	@echo "==> Building X11 test client for native platform..."
	@$(GOBUILD) -o $(BIN_DIR)/$(CLIENT_BINARY) -v $(CLIENT_PKG)
	@echo "Build complete: $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

# Build client for specific platform
build-client-for: ## Build client for specific OS/ARCH (e.g., make build-client-for GOOS=darwin GOARCH=arm64)
	@mkdir -p $(BUILD_DIR)/$(GOOS)-$(GOARCH)
	@echo "==> Building client for $(GOOS)/$(GOARCH)..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $(BUILD_DIR)/$(GOOS)-$(GOARCH)/$(CLIENT_BINARY) $(CLIENT_PKG)
	@ls -lh $(BUILD_DIR)/$(GOOS)-$(GOARCH)/

# Build edge agent (server-side)
build-agent: $(BIN_DIR) ## Build edge agent for native platform
	@echo "==> Building edge agent..."
	@$(GOBUILD) -o $(BIN_DIR)/$(AGENT_BINARY) -v $(AGENT_PKG)
	@echo "Build complete: $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

# Build SOCKS5 client proxy
build-socks: $(BIN_DIR) ## Build SOCKS5 client proxy for native platform
	@echo "==> Building SOCKS5 client proxy..."
	@$(GOBUILD) -o $(BIN_DIR)/$(SOCKS_BINARY) -v $(SOCKS_PKG)
	@echo "Build complete: $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

# Build standalone 9P service
build-9p: $(BIN_DIR) ## Build read-only 9P VFS service
	@echo "==> Building 9P VFS service..."
	@$(GOBUILD) -o $(BIN_DIR)/$(NINEP_BINARY) -v $(NINEP_PKG)
	@echo "Build complete: $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

# Build vfs:// namespace tools (wcp/wls/wmkdir/wtool)
build-vfs: $(BIN_DIR) ## Build vfs:// CLI tools (wcp/wls/wmkdir/wtool)
	@echo "==> Building vfs:// tools..."
	@for b in $(VFS_BINARIES); do $(GOBUILD) -o $(BIN_DIR)/$$b -v ./cmd/$$b || exit 1; done
	@echo "Build complete: $(BIN_DIR)/"

# Build the FUSE mount tool (macFUSE on macOS, libfuse on Linux). Native only.
build-mount: $(BIN_DIR) ## Build wv-mount FUSE tool (macFUSE/libfuse; native only)
	@echo "==> Building wv-mount (FUSE)..."
	@$(GOBUILD) -o $(BIN_DIR)/$(MOUNT_BINARY) -v $(MOUNT_PKG)
	@echo "Build complete: $(BIN_DIR)/$(MOUNT_BINARY)"

# Build native SSH forwarding planner
build-native-forward: $(BIN_DIR) ## Build native SSH forwarding plan generator
	@echo "==> Building native SSH forwarding planner..."
	@$(GOBUILD) -o $(BIN_DIR)/$(NATIVE_FORWARD_BINARY) -v $(NATIVE_FORWARD_PKG)
	@echo "Build complete: $(BIN_DIR)/"
	@ls -lh $(BIN_DIR)/

build-9p-container-plan: ## Print read-only 9P container build plan
	@echo "runtime=$(CONTAINER_RUNTIME)"
	@echo "image=$(NINEP_CONTAINER_IMAGE)"
	@echo "containerfile=$(NINEP_CONTAINERFILE)"
	@echo "command=$(CONTAINER_RUNTIME) build -f $(NINEP_CONTAINERFILE) -t $(NINEP_CONTAINER_IMAGE) ."

build-9p-container: ## Build read-only 9P VFS container image with Docker/Podman/Nerdctl
	@echo "==> Building 9P VFS container image $(NINEP_CONTAINER_IMAGE) with $(CONTAINER_RUNTIME)..."
	@platform_arg=""; \
	if [ -n "$(NINEP_CONTAINER_PLATFORM)" ]; then \
		platform_arg="--platform $(NINEP_CONTAINER_PLATFORM)"; \
	fi; \
	$(CONTAINER_RUNTIME) build $$platform_arg -f $(NINEP_CONTAINERFILE) -t $(NINEP_CONTAINER_IMAGE) .
	@echo "Container image built: $(NINEP_CONTAINER_IMAGE)"

# Build all binaries (server native, client linux x86_64)
build-all-binaries: build-main build-server build-client build-agent build-socks build-9p build-vfs build-native-forward ## Build all binaries
	@echo "==> All binaries built successfully"

# Build all binaries for the current developer platform
build-all-native-binaries: build-main build-server build-client-native build-agent build-socks build-9p build-vfs build-mount build-native-forward ## Build all binaries for current platform
	@echo "==> All native binaries built successfully"

# Show public and internal library package groups used by development builds
list-libraries: ## List Go library packages used by development builds
	@echo "Public library packages:"
	@for pkg in $(LIBRARY_PACKAGES); do echo "  $$pkg"; done
	@echo "Internal library packages:"
	@for pkg in $(INTERNAL_LIBRARY_PACKAGES); do echo "  $$pkg"; done

list-commands: ## List Go command packages built as binaries
	@echo "Command packages:"
	@for pkg in $(COMMAND_PACKAGES); do echo "  $$pkg"; done

build-commands: ## Compile Go command packages into a temporary throwaway directory
	@echo "==> Compiling Go command packages..."
	@tmp_dir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmp_dir"' EXIT; \
	for pkg in $(COMMAND_PACKAGES); do \
		name=$$(basename "$$pkg"); \
		echo "  $$pkg -> $$tmp_dir/$$name"; \
		$(GOBUILD) -o "$$tmp_dir/$$name" "$$pkg"; \
	done

build-libraries: ## Compile public Go library packages without running tests
	@echo "==> Compiling public Go library packages..."
	@$(GOTEST) -run '^$$' $(LIBRARY_PACKAGES)

build-internal-libraries: ## Compile internal Go library packages without running tests
	@echo "==> Compiling internal Go library packages..."
	@$(GOTEST) -run '^$$' $(INTERNAL_LIBRARY_PACKAGES)

build-library-surface: build-libraries build-internal-libraries ## Compile all Go library package surfaces
	@echo "==> Library package surfaces compile"

dev-doctor: ## Check local development prerequisites and print package surfaces
	@echo "==> Checking development prerequisites..."
	@command -v $(GOCMD) >/dev/null || (echo "missing required command: $(GOCMD)" >&2; exit 2)
	@command -v $(PYTHON_BIN) >/dev/null || (echo "missing required command: $(PYTHON_BIN)" >&2; exit 2)
	@$(PYTEST) --version >/dev/null || (echo "missing Python pytest module for $(PYTHON_BIN)" >&2; exit 2)
	@echo "Go:      $$($(GOCMD) version)"
	@echo "Python:  $$($(PYTHON_BIN) --version)"
	@echo "Pytest:  $$($(PYTEST) --version)"
	@$(MAKE) --no-print-directory list-libraries
	@$(MAKE) --no-print-directory list-commands

dev-setup: deps mod-verify dev-doctor ## Prepare and inspect the local development setup
	@echo "==> Development setup ready"

dev-fast: mod-verify fmt-check vet build-library-surface build-commands pytest-collect test-python-build verify-tunnel-policy jepsen-unit ## Run fast developer validation without writing release binaries
	@echo "==> Fast development checks passed"

dev-check: dev-fast build-all-native-binaries test-go ## Run complete local development checks
	@echo "==> Development checks passed"

component-workflows-list: ## List component/workflow workbench targets
	@python3 tools/verification/weaverssh_component_workbench.py list

component-workflows-check: ## Validate component/workflow workbench registry
	@python3 tools/verification/weaverssh_component_workbench.py check

install-dev-plan: ## Print development installation plan for all components/workflows
	@tools/verification/install_weaverssh_development.sh --plan

deploy-local-plan: ## Print local deployment plan for all components/workflows
	@tools/verification/deploy_weaverssh_local.sh --plan

verify-workflows-plan: ## Print verification plan for all components/workflows
	@tools/verification/verify_weaverssh_workflows.sh --phase verify --plan

jepsen-plan: ## Generate a non-mutating Jepsen validation plan for SUT nodes
	@$(PYTHON_BIN) tools/verification/run_weaverssh_jepsen.py --dry-run \
		--nodes "$(JEPSEN_NODES)" \
		--username "$(JEPSEN_USER)" \
		--identity-file "$(JEPSEN_IDENTITY)" \
		--remote-root "$(JEPSEN_REMOTE_ROOT)" \
		--workload "$(JEPSEN_WORKLOAD)" \
		--nemesis "$(JEPSEN_NEMESIS)" \
		--ansible-playbook "$(JEPSEN_ANSIBLE_PLAYBOOK)" \
		--ansible-archive "$(JEPSEN_ANSIBLE_ARCHIVE)" \
		--ansible-checksum "$(JEPSEN_ANSIBLE_CHECKSUM)" \
		--ansible-version "$(JEPSEN_ANSIBLE_VERSION)" \
		--ansible-release "$(JEPSEN_ANSIBLE_RELEASE)" \
		--output artifacts/jepsen/weaverssh_jepsen_plan.json

jepsen-unit: ## Validate Jepsen infrastructure without contacting SUT hosts
	@PYTHONDONTWRITEBYTECODE=1 $(PYTEST) -q -p no:cacheprovider tests/test_weaverssh_jepsen_infrastructure.py

jepsen-system-plan: jepsen-plan ## Alias for planning a Jepsen system-test run

jepsen-system: ## Run Jepsen against disposable SUT nodes; requires ALLOW_DESTRUCTIVE=1
	@if [ "$(ALLOW_DESTRUCTIVE)" != "1" ]; then echo "Set ALLOW_DESTRUCTIVE=1 to run Jepsen against SUT nodes" >&2; exit 2; fi
	@$(PYTHON_BIN) tools/verification/run_weaverssh_jepsen.py --execute --allow-destructive \
		--nodes "$(JEPSEN_NODES)" \
		--username "$(JEPSEN_USER)" \
		--identity-file "$(JEPSEN_IDENTITY)" \
		--remote-root "$(JEPSEN_REMOTE_ROOT)" \
		--workload "$(JEPSEN_WORKLOAD)" \
		--nemesis "$(JEPSEN_NEMESIS)" \
		--ansible-playbook "$(JEPSEN_ANSIBLE_PLAYBOOK)" \
		--ansible-archive "$(JEPSEN_ANSIBLE_ARCHIVE)" \
		--ansible-checksum "$(JEPSEN_ANSIBLE_CHECKSUM)" \
		--ansible-version "$(JEPSEN_ANSIBLE_VERSION)" \
		--ansible-release "$(JEPSEN_ANSIBLE_RELEASE)" \
		--output artifacts/jepsen/weaverssh_jepsen_result.json

jepsen-ansible-install-plan: ## Plan Jepsen workload that installs Ansible then runs the weaverssh Ansible playbook
	@$(PYTHON_BIN) tools/verification/run_weaverssh_jepsen.py --dry-run \
		--nodes "$(JEPSEN_NODES)" \
		--username "$(JEPSEN_USER)" \
		--identity-file "$(JEPSEN_IDENTITY)" \
		--remote-root "$(JEPSEN_REMOTE_ROOT)" \
		--workload ansible-install \
		--nemesis none \
		--ansible-playbook "$(JEPSEN_ANSIBLE_PLAYBOOK)" \
		--ansible-archive "$(JEPSEN_ANSIBLE_ARCHIVE)" \
		--ansible-checksum "$(JEPSEN_ANSIBLE_CHECKSUM)" \
		--ansible-version "$(JEPSEN_ANSIBLE_VERSION)" \
		--ansible-release "$(JEPSEN_ANSIBLE_RELEASE)" \
		--output artifacts/jepsen/weaverssh_ansible_install_plan.json

jepsen-ansible-install-system: ## Execute Jepsen Ansible install workload on disposable SUT nodes; requires ALLOW_DESTRUCTIVE=1
	@if [ "$(ALLOW_DESTRUCTIVE)" != "1" ]; then echo "Set ALLOW_DESTRUCTIVE=1 to install Ansible/weaverssh on SUT nodes" >&2; exit 2; fi
	@$(PYTHON_BIN) tools/verification/run_weaverssh_jepsen.py --execute --allow-destructive \
		--nodes "$(JEPSEN_NODES)" \
		--username "$(JEPSEN_USER)" \
		--identity-file "$(JEPSEN_IDENTITY)" \
		--remote-root "$(JEPSEN_REMOTE_ROOT)" \
		--workload ansible-install \
		--nemesis none \
		--ansible-playbook "$(JEPSEN_ANSIBLE_PLAYBOOK)" \
		--ansible-archive "$(JEPSEN_ANSIBLE_ARCHIVE)" \
		--ansible-checksum "$(JEPSEN_ANSIBLE_CHECKSUM)" \
		--ansible-version "$(JEPSEN_ANSIBLE_VERSION)" \
		--ansible-release "$(JEPSEN_ANSIBLE_RELEASE)" \
		--output artifacts/jepsen/weaverssh_ansible_install_result.json

build-hardened: ## Build native target using hardened profile
	@python3 tools/packaging/build_weaverssh_matrix.py build \
		--target "$$(go env GOOS)/$$(go env GOARCH)" \
		--security-profile $(SECURITY_PROFILE) \
		--build-dir $(BUILD_DIR)/hardened

# Build for Linux
build-linux: $(LINUX_DIR) ## Build integrated server for Linux x86_64
	@echo "==> Building for Linux x86_64..."
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LINUX_DIR)/$(MAIN_BINARY) $(MAIN_PKG)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LINUX_DIR)/$(SERVER_BINARY) $(SERVER_PKG)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LINUX_DIR)/$(CLIENT_BINARY) $(CLIENT_PKG)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LINUX_DIR)/$(AGENT_BINARY) $(AGENT_PKG)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LINUX_DIR)/$(SOCKS_BINARY) $(SOCKS_PKG)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LINUX_DIR)/$(NINEP_BINARY) $(NINEP_PKG)
	@GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(LINUX_DIR)/$(NATIVE_FORWARD_BINARY) $(NATIVE_FORWARD_PKG)
	@echo "Linux build complete: $(LINUX_DIR)/"
	@ls -lh $(LINUX_DIR)/

# Build for macOS x86_64
build-darwin: $(DARWIN_DIR) ## Build integrated server for macOS x86_64
	@echo "==> Building for macOS x86_64..."
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(DARWIN_DIR)/$(MAIN_BINARY) $(MAIN_PKG)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(DARWIN_DIR)/$(SERVER_BINARY) $(SERVER_PKG)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(DARWIN_DIR)/$(CLIENT_BINARY) $(CLIENT_PKG)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(DARWIN_DIR)/$(AGENT_BINARY) $(AGENT_PKG)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(DARWIN_DIR)/$(SOCKS_BINARY) $(SOCKS_PKG)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(DARWIN_DIR)/$(NINEP_BINARY) $(NINEP_PKG)
	@GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(DARWIN_DIR)/$(NATIVE_FORWARD_BINARY) $(NATIVE_FORWARD_PKG)
	@echo "macOS build complete: $(DARWIN_DIR)/"
	@ls -lh $(DARWIN_DIR)/

# Build for macOS ARM64 (Apple Silicon)
build-darwin-arm64: $(DARWIN_ARM64_DIR) ## Build integrated server for macOS ARM64
	@echo "==> Building for macOS ARM64..."
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(DARWIN_ARM64_DIR)/$(MAIN_BINARY) $(MAIN_PKG)
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(DARWIN_ARM64_DIR)/$(SERVER_BINARY) $(SERVER_PKG)
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(DARWIN_ARM64_DIR)/$(CLIENT_BINARY) $(CLIENT_PKG)
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(DARWIN_ARM64_DIR)/$(AGENT_BINARY) $(AGENT_PKG)
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(DARWIN_ARM64_DIR)/$(SOCKS_BINARY) $(SOCKS_PKG)
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(DARWIN_ARM64_DIR)/$(NINEP_BINARY) $(NINEP_PKG)
	@GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(DARWIN_ARM64_DIR)/$(NATIVE_FORWARD_BINARY) $(NATIVE_FORWARD_PKG)
	@echo "macOS ARM64 build complete: $(DARWIN_ARM64_DIR)/"
	@ls -lh $(DARWIN_ARM64_DIR)/

# Build for Windows
build-windows: $(WINDOWS_DIR) ## Build integrated server for Windows x86_64
	@echo "==> Building for Windows x86_64..."
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(WINDOWS_DIR)/$(MAIN_BINARY).exe $(MAIN_PKG)
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(WINDOWS_DIR)/$(SERVER_BINARY).exe $(SERVER_PKG)
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(WINDOWS_DIR)/$(CLIENT_BINARY).exe $(CLIENT_PKG)
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(WINDOWS_DIR)/$(AGENT_BINARY).exe $(AGENT_PKG)
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(WINDOWS_DIR)/$(SOCKS_BINARY).exe $(SOCKS_PKG)
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(WINDOWS_DIR)/$(NINEP_BINARY).exe $(NINEP_PKG)
	@GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(WINDOWS_DIR)/$(NATIVE_FORWARD_BINARY).exe $(NATIVE_FORWARD_PKG)
	@echo "Windows build complete: $(WINDOWS_DIR)/"
	@ls -lh $(WINDOWS_DIR)/

# Usage: make build-cross GOOS=linux GOARCH=amd64
build-cross: ## Build for specified OS/ARCH (e.g., make build-cross GOOS=linux GOARCH=arm64)
	@if [ -z "$(GOOS)" ] || [ -z "$(GOARCH)" ]; then \
		echo "Error: GOOS and GOARCH must be specified"; \
		echo "Usage: make build-cross GOOS=linux GOARCH=amd64"; \
		exit 1; \
	fi
	@CROSS_DIR=$(BUILD_DIR)/$(GOOS)-$(GOARCH); \
	EXT=""; \
	if [ "$(GOOS)" = "windows" ]; then EXT=".exe"; fi; \
	mkdir -p $$CROSS_DIR; \
	echo "==> Building for $(GOOS)/$(GOARCH)..."; \
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $$CROSS_DIR/$(MAIN_BINARY)$${EXT} $(MAIN_PKG); \
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $$CROSS_DIR/$(SERVER_BINARY)$${EXT} $(SERVER_PKG); \
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $$CROSS_DIR/$(CLIENT_BINARY)$${EXT} $(CLIENT_PKG); \
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $$CROSS_DIR/$(AGENT_BINARY)$${EXT} $(AGENT_PKG); \
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $$CROSS_DIR/$(SOCKS_BINARY)$${EXT} $(SOCKS_PKG); \
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $$CROSS_DIR/$(NINEP_BINARY)$${EXT} $(NINEP_PKG); \
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o $$CROSS_DIR/$(NATIVE_FORWARD_BINARY)$${EXT} $(NATIVE_FORWARD_PKG); \
	echo "Build complete: $$CROSS_DIR/"; \
	ls -lh $$CROSS_DIR/

build-matrix-plan: ## Print maintained major architecture build matrix
	@python3 tools/packaging/build_weaverssh_matrix.py plan --preset $(MAJOR_TARGET_PRESET) --security-profile $(SECURITY_PROFILE) --build-dir $(BUILD_DIR)

build-target: ## Build BUILD_TARGET=<goos/goarch[/vN]> using the matrix builder
	@test -n "$(BUILD_TARGET)" || (echo "Set BUILD_TARGET=linux/arm64 or BUILD_TARGET=linux/arm/v7" >&2; exit 2)
	@python3 tools/packaging/build_weaverssh_matrix.py build --target "$(BUILD_TARGET)" --security-profile $(SECURITY_PROFILE) --build-dir $(BUILD_DIR)

build-major-architectures: ## Build all maintained major OS/architecture targets
	@python3 tools/packaging/build_weaverssh_matrix.py build --preset $(MAJOR_TARGET_PRESET) --security-profile $(SECURITY_PROFILE) --build-dir $(BUILD_DIR)

build-linux-major-architectures: ## Build maintained Linux CPU architectures
	@python3 tools/packaging/build_weaverssh_matrix.py build --preset $(LINUX_TARGET_PRESET) --security-profile $(SECURITY_PROFILE) --build-dir $(BUILD_DIR)

# Additional platform targets
build-linux-arm64: ## Build for Linux ARM64
	@mkdir -p $(BUILD_DIR)/linux-arm64
	@echo "==> Building for Linux ARM64..."
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/linux-arm64/$(MAIN_BINARY) $(MAIN_PKG)
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/linux-arm64/$(SERVER_BINARY) $(SERVER_PKG)
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/linux-arm64/$(CLIENT_BINARY) $(CLIENT_PKG)
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/linux-arm64/$(AGENT_BINARY) $(AGENT_PKG)
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/linux-arm64/$(SOCKS_BINARY) $(SOCKS_PKG)
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/linux-arm64/$(NINEP_BINARY) $(NINEP_PKG)
	@GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/linux-arm64/$(NATIVE_FORWARD_BINARY) $(NATIVE_FORWARD_PKG)
	@echo "Linux ARM64 build complete: $(BUILD_DIR)/linux-arm64/"
	@ls -lh $(BUILD_DIR)/linux-arm64/

build-freebsd-amd64: ## Build for FreeBSD x86_64
	@$(MAKE) build-target BUILD_TARGET=freebsd/amd64

build-freebsd-arm64: ## Build for FreeBSD ARM64
	@$(MAKE) build-target BUILD_TARGET=freebsd/arm64

build-openbsd-amd64: ## Build for OpenBSD x86_64
	@$(MAKE) build-target BUILD_TARGET=openbsd/amd64

build-openbsd-arm64: ## Build for OpenBSD ARM64
	@$(MAKE) build-target BUILD_TARGET=openbsd/arm64

# Build for all platforms
build-all: build-linux build-linux-arm64 build-darwin build-darwin-arm64 build-windows build-freebsd-amd64 build-freebsd-arm64 build-openbsd-amd64 build-openbsd-arm64 ## Build for all platform shortcuts
	@echo ""
	@echo "==> All platform builds complete!"
	@echo ""
	@echo "Build artifacts:"
	@find $(BUILD_DIR) -type f \( -name "$(MAIN_BINARY)*" -o -name "$(SERVER_BINARY)*" -o -name "$(CLIENT_BINARY)*" -o -name "$(AGENT_BINARY)*" -o -name "$(SOCKS_BINARY)*" -o -name "$(NINEP_BINARY)*" -o -name "$(NATIVE_FORWARD_BINARY)*" \) | sort

# List available platforms
platforms: ## Show available build platforms
	@echo "Available platform targets:"
	@echo "  build-linux          - Linux x86_64"
	@echo "  build-linux-arm64    - Linux ARM64"
	@echo "  build-linux-major-architectures - Linux amd64, arm64, armv7, 386, ppc64le, s390x, riscv64"
	@echo "  build-darwin         - macOS x86_64 (Intel)"
	@echo "  build-darwin-arm64   - macOS ARM64 (Apple Silicon)"
	@echo "  build-windows        - Windows x86_64"
	@echo "  build-freebsd-amd64  - FreeBSD x86_64"
	@echo "  build-freebsd-arm64  - FreeBSD ARM64"
	@echo "  build-openbsd-amd64  - OpenBSD x86_64"
	@echo "  build-openbsd-arm64  - OpenBSD ARM64"
	@echo "  build-all            - All above platform shortcuts"
	@echo "  build-major-architectures - Linux, macOS, Windows, FreeBSD, and OpenBSD major architectures"
	@echo ""
	@echo "Generic cross-compilation:"
	@echo "  make build-cross GOOS=<os> GOARCH=<arch>"
	@echo "  make build-target BUILD_TARGET=<goos/goarch[/vN]>"
	@echo "  Example: make build-target BUILD_TARGET=linux/arm/v7"

package-plan: ## Print package artifact plans without building packages
	@python3 tools/packaging/weaverssh_packager.py \
		--plan \
		--format deb,rpm,tar.gz,zip,arch,apk,freebsd-pkg,pkg \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--arch $(PACKAGE_ARCH) \
		--prefix $(PACKAGE_PREFIX) \
		--binary-dir $(PACKAGE_BINARY_DIR) \
		--dist-dir $(PACKAGE_DIST_DIR)

package-tar: build-linux ## Build portable Linux tar.gz package
	@python3 tools/packaging/weaverssh_packager.py \
		--format tar.gz \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--arch $(PACKAGE_ARCH) \
		--prefix $(PACKAGE_PREFIX) \
		--binary-dir $(PACKAGE_BINARY_DIR) \
		--dist-dir $(PACKAGE_DIST_DIR)

package-zip: build-linux ## Build portable Linux zip package
	@python3 tools/packaging/weaverssh_packager.py \
		--format zip \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--arch $(PACKAGE_ARCH) \
		--prefix $(PACKAGE_PREFIX) \
		--binary-dir $(PACKAGE_BINARY_DIR) \
		--dist-dir $(PACKAGE_DIST_DIR)

package-deb: build-linux ## Build Debian/Ubuntu .deb package
	@python3 tools/packaging/weaverssh_packager.py \
		--format deb \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--arch $(PACKAGE_ARCH) \
		--prefix /usr \
		--binary-dir $(PACKAGE_BINARY_DIR) \
		--dist-dir $(PACKAGE_DIST_DIR)

package-rpm: build-linux ## Build RHEL/Fedora/SUSE .rpm package
	@python3 tools/packaging/weaverssh_packager.py \
		--format rpm \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--arch $(PACKAGE_ARCH) \
		--prefix /usr \
		--binary-dir $(PACKAGE_BINARY_DIR) \
		--dist-dir $(PACKAGE_DIST_DIR)

package-arch: build-linux ## Build Arch Linux .pkg.tar.zst package
	@python3 tools/packaging/weaverssh_packager.py \
		--format arch \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--arch $(PACKAGE_ARCH) \
		--prefix /usr \
		--binary-dir $(PACKAGE_BINARY_DIR) \
		--dist-dir $(PACKAGE_DIST_DIR)

package-apk: build-linux ## Build Alpine Linux .apk package
	@python3 tools/packaging/weaverssh_packager.py \
		--format apk \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--arch $(PACKAGE_ARCH) \
		--prefix /usr \
		--binary-dir $(PACKAGE_BINARY_DIR) \
		--dist-dir $(PACKAGE_DIST_DIR)

package-freebsd-pkg: ## Build FreeBSD pkg-style archive with +MANIFEST
	@$(MAKE) --no-print-directory build-target BUILD_TARGET=freebsd/$(FREEBSD_PACKAGE_ARCH)
	@python3 tools/packaging/weaverssh_packager.py \
		--format freebsd-pkg \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--arch $(FREEBSD_PACKAGE_ARCH) \
		--prefix /usr/local \
		--binary-dir $(FREEBSD_PACKAGE_BINARY_DIR) \
		--dist-dir $(PACKAGE_DIST_DIR)

package-pkg: build-darwin-arm64 ## Build macOS .pkg package using pkgbuild
	@python3 tools/packaging/weaverssh_packager.py \
		--format pkg \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--arch arm64 \
		--prefix /usr/local \
		--binary-dir $(DARWIN_ARM64_DIR) \
		--dist-dir $(PACKAGE_DIST_DIR)

package-portable: package-tar package-zip ## Build portable archive packages

package-linux: package-deb package-rpm package-arch package-apk ## Build Linux distro packages

package-bsd: package-freebsd-pkg ## Build BSD package artifacts

package-all: package-portable package-linux package-bsd ## Build all portable Linux and FreeBSD package artifacts

binary-dist: ## Build source-free binary distribution tarball for BINARY_DIST_TARGET or current platform
	@args=""; \
	if [ -n "$(BINARY_DIST_TARGET)" ]; then args="$$args --target $(BINARY_DIST_TARGET)"; fi; \
	if [ -n "$(BINARY_DIST_SOURCE_DATE_EPOCH)" ]; then args="$$args --source-date-epoch $(BINARY_DIST_SOURCE_DATE_EPOCH)"; fi; \
	if [ -n "$(BINARY_DIST_SIGN_KEY)" ]; then args="$$args --sign-key $(BINARY_DIST_SIGN_KEY)"; fi; \
	if [ -n "$(BINARY_DIST_GPG_KEY)" ]; then args="$$args --gpg-key $(BINARY_DIST_GPG_KEY)"; fi; \
	if [ -n "$(BINARY_DIST_SIGN)" ]; then args="$$args --sign"; fi; \
	tools/packaging/build_binary_distribution.sh \
		$$args \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--dist-dir $(BINARY_DIST_DIR) \
		--security-profile $(SECURITY_PROFILE)


homebrew-formula-plan: ## Print Homebrew Formula generation plan for HOMEBREW_ARCHIVE(S)
	@test -n "$(HOMEBREW_ARCHIVES)" || (echo "Set HOMEBREW_ARCHIVE=dist/binary/<archive>.tar.gz or HOMEBREW_ARCHIVES='<archive...>'" >&2; exit 2)
	@args=""; \
	for archive in $(HOMEBREW_ARCHIVES); do args="$$args --archive $$archive"; done; \
	if [ -n "$(HOMEBREW_URL_BASE)" ]; then args="$$args --url-base $(HOMEBREW_URL_BASE)"; fi; \
	python3 tools/packaging/build_homebrew_formula.py \
		$$args \
		--license "$(HOMEBREW_LICENSE)" \
		--output "$(HOMEBREW_FORMULA_OUTPUT)" \
		--plan

homebrew-formula: ## Generate Homebrew Formula/weaverssh.rb from binary distribution archives
	@test -n "$(HOMEBREW_ARCHIVES)" || (echo "Set HOMEBREW_ARCHIVE=dist/binary/<archive>.tar.gz or HOMEBREW_ARCHIVES='<archive...>'" >&2; exit 2)
	@args=""; \
	for archive in $(HOMEBREW_ARCHIVES); do args="$$args --archive $$archive"; done; \
	if [ -n "$(HOMEBREW_URL_BASE)" ]; then args="$$args --url-base $(HOMEBREW_URL_BASE)"; fi; \
	python3 tools/packaging/build_homebrew_formula.py \
		$$args \
		--license "$(HOMEBREW_LICENSE)" \
		--output "$(HOMEBREW_FORMULA_OUTPUT)"

package-brew-plan: homebrew-formula-plan ## Alias for Homebrew Formula generation plan

package-brew: homebrew-formula ## Alias for Homebrew Formula generation

repository-manifests-plan: ## Print Nix/Scoop/Chocolatey repository manifest generation plan
	@test -n "$(REPOSITORY_MANIFEST_ARCHIVES)" || (echo "Set REPOSITORY_MANIFEST_ARCHIVE=dist/binary/<archive>.tar.gz or REPOSITORY_MANIFEST_ARCHIVES='<archive...>'" >&2; exit 2)
	@args=""; \
	for archive in $(REPOSITORY_MANIFEST_ARCHIVES); do args="$$args --archive $$archive"; done; \
	for channel in $(REPOSITORY_MANIFEST_CHANNELS); do args="$$args --channel $$channel"; done; \
	if [ -n "$(REPOSITORY_MANIFEST_URL_BASE)" ]; then args="$$args --url-base $(REPOSITORY_MANIFEST_URL_BASE)"; fi; \
	python3 tools/packaging/build_repository_manifests.py \
		$$args \
		--output-dir "$(REPOSITORY_MANIFEST_DIST_DIR)" \
		--plan

repository-manifests: ## Generate Nix/Scoop/Chocolatey repository manifests from binary archives
	@test -n "$(REPOSITORY_MANIFEST_ARCHIVES)" || (echo "Set REPOSITORY_MANIFEST_ARCHIVE=dist/binary/<archive>.tar.gz or REPOSITORY_MANIFEST_ARCHIVES='<archive...>'" >&2; exit 2)
	@args=""; \
	for archive in $(REPOSITORY_MANIFEST_ARCHIVES); do args="$$args --archive $$archive"; done; \
	for channel in $(REPOSITORY_MANIFEST_CHANNELS); do args="$$args --channel $$channel"; done; \
	if [ -n "$(REPOSITORY_MANIFEST_URL_BASE)" ]; then args="$$args --url-base $(REPOSITORY_MANIFEST_URL_BASE)"; fi; \
	python3 tools/packaging/build_repository_manifests.py \
		$$args \
		--output-dir "$(REPOSITORY_MANIFEST_DIST_DIR)"

package-nix-plan: ## Print Nix derivation generation plan
	@$(MAKE) --no-print-directory repository-manifests-plan REPOSITORY_MANIFEST_CHANNELS=nix

package-nix: ## Generate Nix derivation from Linux binary archive
	@$(MAKE) --no-print-directory repository-manifests REPOSITORY_MANIFEST_CHANNELS=nix

package-scoop-plan: ## Print Scoop manifest generation plan
	@$(MAKE) --no-print-directory repository-manifests-plan REPOSITORY_MANIFEST_CHANNELS=scoop

package-scoop: ## Generate Scoop manifest from Windows binary archive
	@$(MAKE) --no-print-directory repository-manifests REPOSITORY_MANIFEST_CHANNELS=scoop

package-chocolatey-plan: ## Print Chocolatey package skeleton generation plan
	@$(MAKE) --no-print-directory repository-manifests-plan REPOSITORY_MANIFEST_CHANNELS=chocolatey

package-chocolatey: ## Generate Chocolatey package skeleton from Windows amd64 binary archive
	@$(MAKE) --no-print-directory repository-manifests REPOSITORY_MANIFEST_CHANNELS=chocolatey

package-snap-plan: ## Print Snap package/project generation plan
	@python3 tools/packaging/build_snap_package.py \
		--plan \
		--binary "$(SNAP_BINARY)" \
		--project-dir "$(SNAP_PROJECT_DIR)" \
		--dist-dir "$(SNAP_DIST_DIR)" \
		--version "$(PACKAGE_VERSION)" \
		--release "$(PACKAGE_RELEASE)" \
		--arch "$(SNAP_ARCH)" \
		--base "$(SNAP_BASE)" \
		--confinement "$(SNAP_CONFINEMENT)" \
		--grade "$(SNAP_GRADE)" \
		--snapcraft "$(SNAPCRAFT)" \
		$(SNAP_PLUG_ARGS)

package-snap-project: ## Generate dist/snap/weaverssh snapcraft project from SNAP_BINARY
	@python3 tools/packaging/build_snap_package.py \
		--binary "$(SNAP_BINARY)" \
		--project-dir "$(SNAP_PROJECT_DIR)" \
		--dist-dir "$(SNAP_DIST_DIR)" \
		--version "$(PACKAGE_VERSION)" \
		--release "$(PACKAGE_RELEASE)" \
		--arch "$(SNAP_ARCH)" \
		--base "$(SNAP_BASE)" \
		--confinement "$(SNAP_CONFINEMENT)" \
		--grade "$(SNAP_GRADE)" \
		--snapcraft "$(SNAPCRAFT)" \
		$(SNAP_PLUG_ARGS)

package-snap: ## Build .snap with snapcraft from SNAP_BINARY; requires snapcraft on Linux
	@python3 tools/packaging/build_snap_package.py \
		--build \
		--binary "$(SNAP_BINARY)" \
		--project-dir "$(SNAP_PROJECT_DIR)" \
		--dist-dir "$(SNAP_DIST_DIR)" \
		--version "$(PACKAGE_VERSION)" \
		--release "$(PACKAGE_RELEASE)" \
		--arch "$(SNAP_ARCH)" \
		--base "$(SNAP_BASE)" \
		--confinement "$(SNAP_CONFINEMENT)" \
		--grade "$(SNAP_GRADE)" \
		--snapcraft "$(SNAPCRAFT)" \
		$(SNAP_PLUG_ARGS)

python-dist: ## Build production Python support distribution tarball
	@args=""; \
	if [ -n "$(PYTHON_DIST_SOURCE_DATE_EPOCH)" ]; then args="$$args --source-date-epoch $(PYTHON_DIST_SOURCE_DATE_EPOCH)"; fi; \
	if [ -n "$(PYTHON_DIST_PROFILE)" ]; then args="$$args --default-profile $(PYTHON_DIST_PROFILE)"; fi; \
	if [ -n "$(PYTHON_DIST_SIGN_KEY)" ]; then args="$$args --sign-key $(PYTHON_DIST_SIGN_KEY)"; fi; \
	if [ -n "$(PYTHON_DIST_GPG_KEY)" ]; then args="$$args --gpg-key $(PYTHON_DIST_GPG_KEY)"; fi; \
	if [ -n "$(PYTHON_DIST_SIGN)" ]; then args="$$args --sign"; fi; \
	if [ -n "$(PYTHON_DIST_DOWNLOAD_WHEELS)" ]; then args="$$args --download-wheels"; fi; \
	python3 tools/packaging/build_python_distribution.py \
		$$args \
		--version $(PACKAGE_VERSION) \
		--release $(PACKAGE_RELEASE) \
		--dist-dir $(PYTHON_DIST_DIR)

python-dist-verify: ## Verify PYTHON_DIST_ARCHIVE=<dist/python/*.tar.gz>
	@test -n "$(PYTHON_DIST_ARCHIVE)" || (echo "Set PYTHON_DIST_ARCHIVE=dist/python/<artifact>.tar.gz" >&2; exit 2)
	@python3 tools/packaging/verify_python_distribution.py \
		--archive "$(PYTHON_DIST_ARCHIVE)" \
		--checksum "$(PYTHON_DIST_ARCHIVE).sha256" \
		--smoke

python-requirements-lock: ## Compile hash-locked Python requirements for PYTHON_DIST_PROFILE
	@tools/packaging/lock_python_requirements.sh --profile "$(PYTHON_DIST_PROFILE)"

python-pip-check: ## Verify this repo is pip-installable without downloading dependencies
	@rm -rf "$(PYTHON_PIP_TARGET)"
	@python3 -m pip install --no-build-isolation --no-deps --target "$(PYTHON_PIP_TARGET)" .
	@PYTHONPATH="$(PYTHON_PIP_TARGET)" python3 -m weaverssh_support --list >/dev/null
	@echo "pip package ok: $(PYTHON_PIP_TARGET)"

ansible-install-plan: ## Print the Ansible wv install command
	@cmd='LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 ansible-playbook -i "$(ANSIBLE_INVENTORY)" "$(ANSIBLE_PLAYBOOK)" -e weaverssh_version=$(ANSIBLE_WV_VERSION) -e weaverssh_release=$(ANSIBLE_WV_RELEASE)'; \
	if [ -n "$(ANSIBLE_WV_ARCHIVE)" ]; then cmd="$$cmd -e weaverssh_archive_path=$(ANSIBLE_WV_ARCHIVE)"; fi; \
	if [ -n "$(ANSIBLE_WV_CHECKSUM)" ]; then cmd="$$cmd -e weaverssh_archive_checksum=$(ANSIBLE_WV_CHECKSUM)"; fi; \
	printf '%s\n' "$$cmd"

ansible-install-wv: ## Install wv with Ansible using ANSIBLE_INVENTORY and optional ANSIBLE_WV_ARCHIVE/CHECKSUM
	@args="-e weaverssh_version=$(ANSIBLE_WV_VERSION) -e weaverssh_release=$(ANSIBLE_WV_RELEASE)"; \
	if [ -n "$(ANSIBLE_WV_ARCHIVE)" ]; then args="$$args -e weaverssh_archive_path=$(ANSIBLE_WV_ARCHIVE)"; fi; \
	if [ -n "$(ANSIBLE_WV_CHECKSUM)" ]; then args="$$args -e weaverssh_archive_checksum=$(ANSIBLE_WV_CHECKSUM)"; fi; \
	LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 ansible-playbook -i "$(ANSIBLE_INVENTORY)" "$(ANSIBLE_PLAYBOOK)" $$args

ansible-install-docker-plan: ## Print the Ansible Docker container wv install command
	@test -n "$(ANSIBLE_DOCKER_CONTAINER)" || (echo "Set ANSIBLE_DOCKER_CONTAINER=<container>" >&2; exit 2)
	@cmd='LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 ansible-playbook "$(ANSIBLE_DOCKER_PLAYBOOK)" -e weaverssh_version=$(ANSIBLE_WV_VERSION) -e weaverssh_release=$(ANSIBLE_WV_RELEASE) -e weaverssh_docker_runtime=$(ANSIBLE_DOCKER_RUNTIME) -e weaverssh_docker_container=$(ANSIBLE_DOCKER_CONTAINER)'; \
	if [ -n "$(ANSIBLE_WV_ARCHIVE)" ]; then cmd="$$cmd -e weaverssh_archive_path=$(ANSIBLE_WV_ARCHIVE)"; fi; \
	if [ -n "$(ANSIBLE_WV_CHECKSUM)" ]; then cmd="$$cmd -e weaverssh_archive_checksum=$(ANSIBLE_WV_CHECKSUM)"; fi; \
	printf '%s\n' "$$cmd"

ansible-install-docker: ## Install wv into a local Docker/compatible container with ANSIBLE_DOCKER_CONTAINER
	@test -n "$(ANSIBLE_DOCKER_CONTAINER)" || (echo "Set ANSIBLE_DOCKER_CONTAINER=<container>" >&2; exit 2)
	@args="-e weaverssh_version=$(ANSIBLE_WV_VERSION) -e weaverssh_release=$(ANSIBLE_WV_RELEASE) -e weaverssh_docker_runtime=$(ANSIBLE_DOCKER_RUNTIME) -e weaverssh_docker_container=$(ANSIBLE_DOCKER_CONTAINER)"; \
	if [ -n "$(ANSIBLE_WV_ARCHIVE)" ]; then args="$$args -e weaverssh_archive_path=$(ANSIBLE_WV_ARCHIVE)"; fi; \
	if [ -n "$(ANSIBLE_WV_CHECKSUM)" ]; then args="$$args -e weaverssh_archive_checksum=$(ANSIBLE_WV_CHECKSUM)"; fi; \
	LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 ansible-playbook "$(ANSIBLE_DOCKER_PLAYBOOK)" $$args

ansible-install-k8s-plan: ## Print the Ansible Kubernetes pod wv install command
	@test -n "$(ANSIBLE_K8S_POD)" || (echo "Set ANSIBLE_K8S_POD=<pod>" >&2; exit 2)
	@cmd='LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 ansible-playbook "$(ANSIBLE_K8S_PLAYBOOK)" -e weaverssh_version=$(ANSIBLE_WV_VERSION) -e weaverssh_release=$(ANSIBLE_WV_RELEASE) -e weaverssh_kubernetes_namespace=$(ANSIBLE_K8S_NAMESPACE) -e weaverssh_kubernetes_pod=$(ANSIBLE_K8S_POD)'; \
	if [ -n "$(ANSIBLE_K8S_CONTAINER)" ]; then cmd="$$cmd -e weaverssh_kubernetes_container=$(ANSIBLE_K8S_CONTAINER)"; fi; \
	if [ -n "$(ANSIBLE_WV_ARCHIVE)" ]; then cmd="$$cmd -e weaverssh_archive_path=$(ANSIBLE_WV_ARCHIVE)"; fi; \
	if [ -n "$(ANSIBLE_WV_CHECKSUM)" ]; then cmd="$$cmd -e weaverssh_archive_checksum=$(ANSIBLE_WV_CHECKSUM)"; fi; \
	printf '%s\n' "$$cmd"

ansible-install-k8s: ## Install wv into a Kubernetes pod with ANSIBLE_K8S_NAMESPACE/POD/CONTAINER
	@test -n "$(ANSIBLE_K8S_POD)" || (echo "Set ANSIBLE_K8S_POD=<pod>" >&2; exit 2)
	@args="-e weaverssh_version=$(ANSIBLE_WV_VERSION) -e weaverssh_release=$(ANSIBLE_WV_RELEASE) -e weaverssh_kubernetes_namespace=$(ANSIBLE_K8S_NAMESPACE) -e weaverssh_kubernetes_pod=$(ANSIBLE_K8S_POD)"; \
	if [ -n "$(ANSIBLE_K8S_CONTAINER)" ]; then args="$$args -e weaverssh_kubernetes_container=$(ANSIBLE_K8S_CONTAINER)"; fi; \
	if [ -n "$(ANSIBLE_WV_ARCHIVE)" ]; then args="$$args -e weaverssh_archive_path=$(ANSIBLE_WV_ARCHIVE)"; fi; \
	if [ -n "$(ANSIBLE_WV_CHECKSUM)" ]; then args="$$args -e weaverssh_archive_checksum=$(ANSIBLE_WV_CHECKSUM)"; fi; \
	LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 ansible-playbook "$(ANSIBLE_K8S_PLAYBOOK)" $$args

ansible-syntax-check: ## Run ansible-playbook --syntax-check when Ansible is installed
	@if command -v ansible-playbook >/dev/null 2>&1; then \
		for playbook in "$(ANSIBLE_PLAYBOOK)" "$(ANSIBLE_DOCKER_PLAYBOOK)" "$(ANSIBLE_K8S_PLAYBOOK)"; do \
			LC_ALL=en_US.UTF-8 LANG=en_US.UTF-8 ansible-playbook -i "$(ANSIBLE_SYNTAX_INVENTORY)" "$$playbook" --syntax-check; \
		done; \
	else \
		echo "ansible-playbook not found; install ansible-core to run syntax check"; \
	fi
package-portable-linux-major-architectures: build-linux-major-architectures ## Build tar.gz and zip packages for maintained Linux architectures
	@set -e; \
	for arch in $(LINUX_PACKAGE_ARCHES); do \
		dir="$(BUILD_DIR)/linux-$$arch"; \
		if [ ! -d "$$dir" ]; then echo "Missing build directory $$dir" >&2; exit 2; fi; \
		echo "==> Packaging Linux $$arch portable artifacts from $$dir"; \
		python3 tools/packaging/weaverssh_packager.py \
			--format tar.gz \
			--format zip \
			--version $(PACKAGE_VERSION) \
			--release $(PACKAGE_RELEASE) \
			--arch $$arch \
			--prefix /usr \
			--binary-dir "$$dir" \
			--dist-dir $(PACKAGE_DIST_DIR); \
	done

install-package-plan: ## Print install commands for PACKAGE_FILE=<artifact>
	@test -n "$(PACKAGE_FILE)" || (echo "Set PACKAGE_FILE=dist/packages/<artifact>" >&2; exit 2)
	@python3 tools/packaging/install_weaverssh_package.py plan "$(PACKAGE_FILE)"

install-package: ## Install PACKAGE_FILE=<artifact> using the OS package manager
	@test -n "$(PACKAGE_FILE)" || (echo "Set PACKAGE_FILE=dist/packages/<artifact>" >&2; exit 2)
	@python3 tools/packaging/install_weaverssh_package.py install "$(PACKAGE_FILE)"

install-runtime-deps-plan: ## Print runtime dependency install commands for this host
	@$(WV) deps plan

install-runtime-deps-status: ## Inspect whether runtime dependencies are installed
	@$(WV) deps status --log-file "$(DEPS_LOG)"

install-runtime-deps: ## Install missing runtime dependencies and append DEPS_LOG
	@$(WV) deps install --yes --log-file "$(DEPS_LOG)"

install-runtime-deps-replace: ## Force reinstall/replace runtime dependencies and append DEPS_LOG
	@$(WV) deps install --yes --replace --force --confirm-force --log-file "$(DEPS_LOG)"

install-build-deps-plan: ## Print runtime + build/package dependency install commands for this host
	@$(WV) deps plan --include-build

install-build-deps-status: ## Inspect whether runtime + build/package dependencies are installed
	@$(WV) deps status --include-build --log-file "$(DEPS_LOG)"

install-build-deps: ## Install missing runtime + build/package dependencies and append DEPS_LOG
	@$(WV) deps install --include-build --yes --log-file "$(DEPS_LOG)"

install-build-deps-replace: ## Force reinstall/replace runtime + build/package dependencies and append DEPS_LOG
	@$(WV) deps install --include-build --yes --replace --force --confirm-force --log-file "$(DEPS_LOG)"

platform-setup-plan: ## Detect deps, SSH keys/configs, and planned wv connection setup for PLATFORM=<auto|linux|wsl|windows|macos|freebsd|aix|zos-linux>
	@python3 tools/packaging/linux_setup.py plan --platform "$(or $(PLATFORM),auto)"

platform-setup-script: ## Emit setup script for PLATFORM=<auto|linux|wsl|windows|macos|freebsd|aix|zos-linux>
	@python3 tools/packaging/linux_setup.py emit-script --platform "$(or $(PLATFORM),auto)"

linux-setup-plan: ## Detect Linux deps, SSH keys/configs, and planned wv connection setup
	@python3 tools/packaging/linux_setup.py plan --platform linux

linux-setup-script: ## Emit a shell script that configures detected Linux wv connection profile(s)
	@python3 tools/packaging/linux_setup.py emit-script --platform linux

# Run tests
fmt-check: ## Verify Go source files are gofmt-formatted without modifying them
	@echo "==> Checking Go formatting..."
	@files=$$(find . \
		-path ./.git -prune -o \
		-path ./build -prune -o \
		-path ./artifacts -prune -o \
		-path ./verification_results -prune -o \
		-name '*.go' -print); \
	if [ -n "$$files" ]; then \
		unformatted=$$(gofmt -l $$files); \
		if [ -n "$$unformatted" ]; then \
			echo "Go files need gofmt:" >&2; \
			echo "$$unformatted" >&2; \
			exit 1; \
		fi; \
	fi

vet: ## Run go vet over all Go packages
	@echo "==> Running go vet..."
	@$(GOVET) ./...

pytest-collect: ## Verify Python tests collect successfully without running them
	@echo "==> Collecting Python tests..."
	@PYTHONDONTWRITEBYTECODE=1 $(PYTEST) --collect-only -q -p no:cacheprovider tests >/tmp/weaverssh_pytest_collect.log
	@tail -1 /tmp/weaverssh_pytest_collect.log

test-go: ## Run Go tests without race detector
	@echo "==> Running Go tests..."
	@$(GOTEST) ./...

test-go-race: ## Run Go tests with race detector
	@echo "==> Running Go race tests..."
	@$(GOTEST) -v -race ./...

test-python-build: ## Run Python build/development support tests
	@PYTHONDONTWRITEBYTECODE=1 $(PYTEST) -q -p no:cacheprovider \
		tests/test_weaverssh_build_matrix.py \
		tests/test_weaverssh_packaging.py \
		tests/test_weaverssh_development_build.py \
		tests/test_weaverssh_component_workbench.py

test-authproof-agent-flags: ## Run unit coverage for authproof ssh-agent/gpg-agent flags
	@tools/verification/test_authproof_agent_flags.sh

test-authproof-agent-integration: ## Build commands and run local authproof ssh-agent/gpg-agent integration tests
	@tools/verification/test_authproof_agent_integration.sh

test: test-go-race ## Run Go tests with race detector

verify-tunnel-policy: ## Verify weaverssh tunnel mechanism policy
	@python3 tools/verification/verify_weaverssh_tunnel_policy.py

# Clean build artifacts
clean: ## Remove build directory and binaries
	@echo "==> Cleaning build artifacts..."
	@$(GOCLEAN)
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

# Run main integrated server in X11 mode
run-main: build-main ## Build and run integrated server (X11 mode)
	@echo "==> Starting integrated X11/WebSocket server..."
	@$(BIN_DIR)/$(MAIN_BINARY) -mode x11 -port 6002

# Run in hybrid mode
run-hybrid: build-main ## Build and run in hybrid mode
	@echo "==> Starting in hybrid mode..."
	@$(BIN_DIR)/$(MAIN_BINARY) -mode hybrid -port 6004

# Run standalone server
run-server: build-server ## Build and run standalone X11 server
	@echo "==> Starting standalone X11 server..."
	@$(BIN_DIR)/$(SERVER_BINARY)

# Run test client (builds for Linux, then runs if on Linux)
run-client: build-client ## Build and run X11 test client
	@if [ "$$(uname -s)" = "Linux" ]; then \
		echo "==> Starting X11 test client..."; \
		$(LINUX_DIR)/$(CLIENT_BINARY); \
	else \
		echo "Client built for Linux. Use 'make build-client-native && ./build/bin/$(CLIENT_BINARY)' to run on $$(uname -s)"; \
	fi

# Format Go code
fmt: ## Format Go source code
	@echo "==> Formatting code..."
	@$(GOCMD) fmt ./...

# Verify Go modules
mod-verify: ## Verify Go module dependencies
	@echo "==> Verifying modules..."
	@$(GOMOD) verify

# Initialize Go module
init: ## Initialize Go module (if needed)
	@if [ ! -f go.mod ]; then \
		echo "==> Initializing Go module..."; \
		$(GOMOD) init weaverssh; \
	else \
		echo "go.mod already exists"; \
	fi

# Show build information
info: ## Display build information
	@echo "Build Information:"
	@echo "  Go Version:    $$($(GOCMD) version)"
	@echo ""
	@echo "Binaries:"
	@echo "  Main:   $(MAIN_BINARY)"
	@echo "  Server: $(SERVER_BINARY)"
	@echo "  Client: $(CLIENT_BINARY)"
	@echo "  Agent:  $(AGENT_BINARY)"
	@echo "  SOCKS:  $(SOCKS_BINARY)"
	@echo "  9P:     $(NINEP_BINARY)"
	@echo "  Native: $(NATIVE_FORWARD_BINARY)"
	@echo ""
	@echo "Command Packages:"
	@echo "  Main:   $(MAIN_PKG)"
	@echo "  Server: $(SERVER_PKG)"
	@echo "  Client: $(CLIENT_PKG)"
	@echo "  Agent:  $(AGENT_PKG)"
	@echo "  SOCKS:  $(SOCKS_PKG)"
	@echo "  9P:     $(NINEP_PKG)"
	@echo "  Native: $(NATIVE_FORWARD_PKG)"
	@echo ""
	@echo "Build Directory: $(BUILD_DIR)"
	@echo ""
	@echo "Development Package Groups:"
	@echo "  Commands:  $(COMMAND_PACKAGES)"
	@echo "  Public:    $(LIBRARY_PACKAGES)"
	@echo "  Internal:  $(INTERNAL_LIBRARY_PACKAGES)"
	@echo ""
	@echo "Current Platform:"
	@echo "  OS:   $$(go env GOOS)"
	@echo "  Arch: $$(go env GOARCH)"
	@echo ""
	@echo "Run 'make platforms' to see all build targets"
