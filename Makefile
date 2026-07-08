# Makefile for building multi-arch ROSA Boundary container
IMAGE_NAME := rosa-boundary
TAG := latest
FULL_IMAGE := $(IMAGE_NAME):$(TAG)

# Architecture-specific image tags
AMD64_IMAGE := $(IMAGE_NAME):$(TAG)-amd64
ARM64_IMAGE := $(IMAGE_NAME):$(TAG)-arm64

# Go CLI
CLI_BIN := bin/rosa-boundary
CLI_VERSION ?= dev
CLI_LDFLAGS := -ldflags "-X github.com/openshift/rosa-boundary/internal/cmd.Version=$(CLI_VERSION)"

.PHONY: all build build-amd64 build-arm64 manifest clean help \
        build-cli install-cli test-cli fmt lint staticcheck test-shell lint-shell \
        build-ci-image ci-all ci-test-shell ci-lint-shell \
        ci-build-cli ci-test-cli ci-fmt ci-fmt-fix ci-lint ci-staticcheck \
        validate-findings convert-sarif upload-sarif

# Default target: build both architectures and create manifest
all: build manifest

# Build both architectures
build: build-amd64 build-arm64

# Build AMD64/x86_64 variant
build-amd64:
	@echo "Building AMD64 variant..."
	podman build --platform linux/amd64 -t $(AMD64_IMAGE) -f Containerfile .

# Build ARM64 variant
build-arm64:
	@echo "Building ARM64 variant..."
	podman build --platform linux/arm64 -t $(ARM64_IMAGE) -f Containerfile .

# Create manifest list combining both architectures
manifest: build
	@echo "Creating manifest list..."
	podman manifest rm $(FULL_IMAGE) 2>/dev/null || true
	podman manifest create $(FULL_IMAGE)
	podman manifest add $(FULL_IMAGE) $(AMD64_IMAGE)
	podman manifest add $(FULL_IMAGE) $(ARM64_IMAGE)
	@echo "Manifest created: $(FULL_IMAGE)"
	@echo "Inspect with: podman manifest inspect $(FULL_IMAGE)"

# Clean up all images and manifests
clean:
	@echo "Removing images and manifests..."
	podman manifest rm $(FULL_IMAGE) 2>/dev/null || true
	podman rmi $(AMD64_IMAGE) 2>/dev/null || true
	podman rmi $(ARM64_IMAGE) 2>/dev/null || true
	@echo "Cleanup complete"

# LocalStack integration testing
.PHONY: localstack-up localstack-down localstack-logs test-localstack test-localstack-fast

localstack-up: ## Start LocalStack Pro with all services (podman)
	@if [ ! -f tests/localstack/.env ]; then \
		echo "ERROR: tests/localstack/.env not found"; \
		echo "Copy .env.example to .env and add LOCALSTACK_AUTH_TOKEN"; \
		exit 1; \
	fi
	@echo "Ensuring podman is ready..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		echo "Detected macOS - checking podman machine..."; \
		podman machine list 2>/dev/null | grep -q "Currently running" || \
			(echo "Starting podman machine..."; podman machine start || true); \
	else \
		echo "Detected Linux - checking podman socket..."; \
		systemctl --user is-active podman.socket >/dev/null 2>&1 || systemctl --user start podman.socket; \
	fi
	cd tests/localstack && podman-compose up -d
	@echo "Waiting for LocalStack to be ready..."
	@timeout 120 bash -c 'until curl -s http://localhost:4566/_localstack/health | grep -q "\"ecs\""; do sleep 5; done' || (echo "LocalStack startup timed out"; exit 1)
	@echo "LocalStack Pro ready with ECS and EFS support"

localstack-down: ## Stop LocalStack and clean up
	cd tests/localstack && podman-compose down -v

localstack-logs: ## View LocalStack logs
	cd tests/localstack && podman-compose logs -f localstack

test-localstack: localstack-up ## Run all LocalStack integration tests
	pytest tests/localstack/integration/ -v --tb=short || (make localstack-down; exit 1)
	$(MAKE) localstack-down

test-localstack-fast: ## Run LocalStack tests without slow tests (faster)
	@if ! curl -s http://localhost:4566/_localstack/health > /dev/null 2>&1; then \
		echo "ERROR: LocalStack not running. Start with: make localstack-up"; \
		exit 1; \
	fi
	pytest tests/localstack/integration/ -v -m "not slow" --tb=short

# Lambda unit testing
.PHONY: test-lambda test-lambda-reap-tasks test-lambda-create-investigation

test-lambda: test-lambda-reap-tasks test-lambda-create-investigation ## Run all Lambda unit tests

test-lambda-reap-tasks: ## Run reap-tasks Lambda unit tests
	@echo "Running reap-tasks unit tests..."
	cd lambda/reap-tasks && uv run --with boto3 python -m unittest test_handler -v

test-lambda-create-investigation: ## Run create-investigation Lambda unit tests
	@echo "Running create-investigation unit tests..."
	cd lambda/create-investigation && uv run pytest test_handler.py -v

staticcheck: ## Run staticcheck on host (requires staticcheck installed)
	@echo "Running staticcheck..."
	staticcheck ./...

# Go CLI targets — run on the host (require Go toolchain installed)
build-cli: ## Build the rosa-boundary Go CLI binary
	@echo "Building rosa-boundary CLI..."
	@mkdir -p bin
	go build $(CLI_LDFLAGS) -o $(CLI_BIN) ./cmd/rosa-boundary/

install-cli: ## Install the rosa-boundary CLI to GOBIN
	@echo "Installing rosa-boundary to GOBIN..."
	go install $(CLI_LDFLAGS) ./cmd/rosa-boundary/

test-cli: ## Run Go unit tests for the CLI
	@echo "Running CLI unit tests..."
	go test ./...

fmt: ## Format Go and shell code (requires gofmt; shfmt optional)
	@echo "Formatting Go code..."
	gofmt -w .
	@echo "Formatting shell scripts..."
	@if command -v shfmt > /dev/null 2>&1; then \
		shfmt -w -i 4 entrypoint.sh skel/sre/.bashrc.d/*.bashrc skel/sre/.local/bin/sre-login; \
	else \
		echo "shfmt not installed — run 'make ci-fmt-fix' to format shell scripts in container"; \
	fi

lint: ## Lint Go code (requires golangci-lint installed)
	@echo "Linting Go code..."
	golangci-lint run ./...

# ── Containerized CI variants ────────────────────────────────────────────────
# Mirror the host targets but run inside the CI image (build/Containerfile.test).
# Used by Prow and for local CI validation without host tooling.
# Only podman is required on the host.

CI_IMAGE := rosa-boundary-ci:latest

build-ci-image: ## Build the CI runner container image (cached)
	@echo "Building CI runner image..."
	podman build --tag $(CI_IMAGE) --file build/Containerfile.test .
ci-all: ci-lint-shell ci-test-shell ci-lint ci-staticcheck ci-test-cli ci-fmt ## Run all CI checks (containerized)
	@echo "All CI checks passed"

ci-test-shell: build-ci-image ## Run bats-core shell unit tests (containerized)
	@echo "Running shell unit tests in container..."
	podman run --rm \
		--volume "$(CURDIR):/workspace:ro,Z" \
		--workdir /workspace \
		$(CI_IMAGE) \
		bats tests/shell/entrypoint.bats tests/shell/sre-login.bats tests/shell/bashrc.d/

ci-lint-shell: build-ci-image ## Run shellcheck on all shell scripts (containerized)
	@echo "Running shellcheck in container..."
	podman run --rm \
		--volume "$(CURDIR):/workspace:ro,Z" \
		--workdir /workspace \
		$(CI_IMAGE) \
		shellcheck entrypoint.sh \
			skel/sre/.local/bin/sre-login \
			skel/sre/.bashrc.d/*.bashrc \
			skel/sre/.bashrc
	@echo "All shell scripts passed shellcheck"

ci-build-cli: build-ci-image ## Build the Go CLI binary (containerized)
	@echo "Building rosa-boundary CLI in container..."
	podman run --rm \
		--volume "$(CURDIR):/workspace:Z" \
		--workdir /workspace \
		$(CI_IMAGE) \
		go build $(CLI_LDFLAGS) -o $(CLI_BIN) ./cmd/rosa-boundary/

ci-test-cli: build-ci-image ## Run Go unit tests (containerized)
	@echo "Running CLI unit tests in container..."
	podman run --rm \
		--volume "$(CURDIR):/workspace:ro,Z" \
		--workdir /workspace \
		$(CI_IMAGE) \
		go test ./...

ci-fmt-fix: build-ci-image ## Fix Go and shell formatting (containerized, writes to files)
	@echo "Fixing code formatting in container..."
	podman run --rm \
		--volume "$(CURDIR):/workspace:Z" \
		--workdir /workspace \
		$(CI_IMAGE) \
		sh -c "gofmt -w . && shfmt -w -i 4 entrypoint.sh skel/sre/.bashrc.d/*.bashrc skel/sre/.local/bin/sre-login"

ci-fmt: build-ci-image ## Check Go and shell formatting (containerized, fails on diff)
	@echo "Checking code formatting in container..."
	podman run --rm \
		--volume "$(CURDIR):/workspace:ro,Z" \
		--workdir /workspace \
		$(CI_IMAGE) \
		sh -c '\
			FAIL=0; \
			GOFMT_OUT=$$(gofmt -l .); \
			if [ -n "$$GOFMT_OUT" ]; then \
				echo "gofmt: the following files need formatting:"; \
				echo "$$GOFMT_OUT"; \
				FAIL=1; \
			fi; \
			SHFMT_OUT=$$(shfmt -d -i 4 entrypoint.sh skel/sre/.bashrc.d/*.bashrc skel/sre/.local/bin/sre-login); \
			if [ -n "$$SHFMT_OUT" ]; then \
				echo "shfmt: the following files need formatting:"; \
				echo "$$SHFMT_OUT"; \
				FAIL=1; \
			fi; \
			if [ $$FAIL -eq 0 ]; then echo "All files correctly formatted"; fi; \
		exit $$FAIL'

ci-lint: build-ci-image ## Lint Go code (containerized)
	@echo "Linting Go code in container..."
	podman run --rm \
		--volume "$(CURDIR):/workspace:ro,Z" \
		--workdir /workspace \
		$(CI_IMAGE) \
		golangci-lint run ./...

ci-staticcheck: build-ci-image ## Run staticcheck (containerized)
	@echo "Running staticcheck in container..."
	podman run --rm \
		--volume "$(CURDIR):/workspace:ro,Z" \
		--workdir /workspace \
		$(CI_IMAGE) \
		staticcheck ./...

# Shell testing and linting — run on host (require bats + shellcheck installed)
test-shell: ## Run bats-core unit tests for shell scripts
	@echo "Running shell unit tests..."
	bats tests/shell/entrypoint.bats tests/shell/sre-login.bats tests/shell/bashrc.d/

lint-shell: ## Run shellcheck on all shell scripts (blocking)
	@echo "Running shellcheck..."
	shellcheck entrypoint.sh \
		skel/sre/.local/bin/sre-login \
		skel/sre/.bashrc.d/*.bashrc \
		skel/sre/.bashrc
	@echo "All shell scripts passed shellcheck"

# Security findings
validate-findings: ## Validate adversary-findings.json schema
	@python3 scripts/findings-to-sarif.py --validate --input adversary-findings.json

convert-sarif: ## Convert adversary-findings.json to SARIF format
	@python3 scripts/findings-to-sarif.py --input adversary-findings.json --output adversary-findings.sarif

upload-sarif: convert-sarif ## Convert findings to SARIF and upload to GitHub code scanning
	@if ! command -v gh > /dev/null 2>&1; then \
		echo "ERROR: gh CLI not installed. Install from https://cli.github.com/"; \
		exit 1; \
	fi
	@echo "Uploading SARIF to GitHub code scanning..."
	gh api \
		--method POST \
		-H "Accept: application/vnd.github+json" \
		"/repos/{owner}/{repo}/code-scanning/sarifs" \
		-f "commit_sha=$$(git rev-parse HEAD)" \
		-f "ref=$$(git symbolic-ref HEAD)" \
		-f "sarif=$$(gzip -c adversary-findings.sarif | base64)"
	@echo "SARIF uploaded successfully"

# Show help
help:
	@echo "ROSA Boundary Container Build Targets:"
	@echo "  make all          - Build both architectures and create manifest (default)"
	@echo "  make build        - Build both AMD64 and ARM64 variants"
	@echo "  make build-amd64  - Build only AMD64 variant"
	@echo "  make build-arm64  - Build only ARM64 variant"
	@echo "  make manifest     - Create multi-arch manifest list"
	@echo "  make clean        - Remove all images and manifests"
	@echo ""
	@echo "Go CLI Targets (run on host, require Go toolchain):"
	@echo "  make build-cli    - Build the rosa-boundary CLI binary (./bin/rosa-boundary)"
	@echo "  make install-cli  - Install CLI to GOBIN (~/go/bin)"
	@echo "  make test-cli     - Run CLI unit tests"
	@echo ""
	@echo "LocalStack Testing Targets:"
	@echo "  make localstack-up         - Start LocalStack Pro with all services"
	@echo "  make localstack-down       - Stop LocalStack and clean up"
	@echo "  make localstack-logs       - View LocalStack logs"
	@echo "  make test-localstack       - Run all LocalStack integration tests"
	@echo "  make test-localstack-fast  - Run LocalStack tests (skip slow tests)"
	@echo ""
	@echo "Lambda Unit Testing Targets:"
	@echo "  make test-lambda                      - Run all Lambda unit tests"
	@echo "  make test-lambda-reap-tasks           - Run reap-tasks unit tests"
	@echo "  make test-lambda-create-investigation - Run create-investigation unit tests"
	@echo ""
	@echo "Code Quality (run on host, require tools installed):"
	@echo "  make fmt            - Format Go (gofmt) and shell (shfmt) code"
	@echo "  make lint           - Lint Go code (golangci-lint)"
	@echo "  make staticcheck    - Run staticcheck static analysis"
	@echo "  make test-shell     - Run bats-core shell unit tests"
	@echo "  make lint-shell     - Run shellcheck on all shell scripts"
	@echo ""
	@echo "Containerized CI (only podman required — mirrors Prow jobs):"
	@echo "  make ci-all             - Run ALL CI checks (one command)"
	@echo "  make build-ci-image     - Build the CI runner container (cached)"
	@echo "  make ci-test-shell      - Run bats-core shell unit tests"
	@echo "  make ci-lint-shell      - Run shellcheck on all shell scripts"
	@echo "  make ci-build-cli       - Build Go CLI binary"
	@echo "  make ci-test-cli        - Run Go unit tests"
	@echo "  make ci-fmt             - Check Go and shell formatting (fails on diff)"
	@echo "  make ci-fmt-fix         - Fix Go and shell formatting (writes)"
	@echo "  make ci-lint            - Lint Go code (golangci-lint)"
	@echo "  make ci-staticcheck     - Run staticcheck"
	@echo ""
	@echo "Security Findings Targets:"
	@echo "  make validate-findings  - Validate adversary-findings.json schema"
	@echo "  make convert-sarif      - Convert findings JSON to SARIF format"
	@echo "  make upload-sarif       - Convert and upload SARIF to GitHub code scanning"
	@echo ""
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Current configuration:"
	@echo "  Image name: $(FULL_IMAGE)"
	@echo "  AMD64 tag:  $(AMD64_IMAGE)"
	@echo "  ARM64 tag:  $(ARM64_IMAGE)"
	@echo "  CLI binary: $(CLI_BIN)"
	@echo "  CLI version: $(CLI_VERSION)"
