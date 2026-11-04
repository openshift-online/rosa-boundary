# Makefile for building multi-arch ROSA Boundary container
IMAGE_NAME := rosa-boundary
TAG := latest
FULL_IMAGE := $(IMAGE_NAME):$(TAG)

# Architecture-specific image tags
AMD64_IMAGE := $(IMAGE_NAME):$(TAG)-amd64
ARM64_IMAGE := $(IMAGE_NAME):$(TAG)-arm64

# Build args
CACHE ?=
REQUIRE_GITHUB_TOKEN ?= false

# Go CLI
CLI_BIN := bin/rosa-boundary
CLI_VERSION ?= dev
CLI_LDFLAGS := -ldflags "-X github.com/openshift-online/rosa-boundary/internal/cmd.Version=$(CLI_VERSION)"

.PHONY: all build build-amd64 build-arm64 manifest clean help \
        build-cli install-cli test-cli test-coverage codecov fmt lint \
        validate-findings convert-sarif upload-sarif \
        test-github-dl test test-shell test-all check lint-shell pre-commit

# Default target: build both architectures and create manifest
all: build manifest

# Build both architectures
build: build-amd64 build-arm64

# Build AMD64/x86_64 variant
build-amd64:
	@echo "Building AMD64 variant..."

	podman build --platform linux/amd64 --build-arg REQUIRE_GITHUB_TOKEN=$(REQUIRE_GITHUB_TOKEN) \
		$$([ -n "$$GITHUB_TOKEN" ] && echo "--secret id=GITHUB_TOKEN,env=GITHUB_TOKEN") \
		$$([ -n "$$GITHUB_APP_ID" ] && echo "--secret id=rosa-boundary-github-app/GITHUB_APP_ID,env=GITHUB_APP_ID") \
		$$([ -n "$$GITHUB_APP_PEM" ] && echo "--secret id=rosa-boundary-github-app/GITHUB_APP_PEM,env=GITHUB_APP_PEM") \
		$$([ -n "$$GITHUB_APP_INSTALL_ID" ] && echo "--secret id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID,env=GITHUB_APP_INSTALL_ID") \
		$(CACHE) -t $(AMD64_IMAGE) -f Containerfile .

# Build ARM64 variant
build-arm64:
	@echo "Building ARM64 variant..."

	podman build --platform linux/arm64 --build-arg REQUIRE_GITHUB_TOKEN=$(REQUIRE_GITHUB_TOKEN) \
		$$([ -n "$$GITHUB_TOKEN" ] && echo "--secret id=GITHUB_TOKEN,env=GITHUB_TOKEN") \
		$$([ -n "$$GITHUB_APP_ID" ] && echo "--secret id=rosa-boundary-github-app/GITHUB_APP_ID,env=GITHUB_APP_ID") \
		$$([ -n "$$GITHUB_APP_PEM" ] && echo "--secret id=rosa-boundary-github-app/GITHUB_APP_PEM,env=GITHUB_APP_PEM") \
		$$([ -n "$$GITHUB_APP_INSTALL_ID" ] && echo "--secret id=rosa-boundary-github-app/GITHUB_APP_INSTALL_ID,env=GITHUB_APP_INSTALL_ID") \
		$(CACHE) -t $(ARM64_IMAGE) -f Containerfile .

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
.PHONY: localstack-up localstack-down localstack-logs localstack-ready test-localstack test-localstack-fast test-localstack-ci

localstack-up: ## Start LocalStack Pro with all services (podman)
	@if [ ! -f tests/localstack/.env ]; then \
		echo "ERROR: tests/localstack/.env not found"; \
		echo "Copy .env.example to .env and add LOCALSTACK_AUTH_TOKEN"; \
		exit 1; \
	fi
	@echo "Ensuring podman is ready..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		echo "Detected macOS - checking podman machine..."; \
		podman info >/dev/null 2>&1 || \
			(echo "Starting podman machine..."; podman machine start); \
	else \
		echo "Detected Linux - checking podman socket..."; \
		podman info >/dev/null 2>&1 || systemctl --user start podman.socket; \
	fi
	bash tests/localstack/compose.sh up -d
	@echo "Waiting for LocalStack to be ready..."
	@timeout 120 bash -c 'until python3 tests/localstack/check_ready.py >/dev/null 2>&1; do sleep 5; done' || { python3 tests/localstack/check_ready.py; exit 1; }
	@echo "LocalStack Pro ready with ECS and EFS support"

localstack-down: ## Stop LocalStack and clean up
	bash tests/localstack/compose.sh down -v

localstack-logs: ## View LocalStack logs
	bash tests/localstack/compose.sh logs -f localstack

localstack-ready: ## Assert live LocalStack health and required service readiness
	python3 tests/localstack/check_ready.py

test-localstack: localstack-up ## Run all LocalStack integration tests
	$(MAKE) localstack-ready
	uv run --group localstack pytest tests/localstack/integration/ -v --tb=short -ra || (make localstack-down; exit 1)
	$(MAKE) localstack-down

test-localstack-fast: localstack-ready ## Run LocalStack tests without slow tests (faster)
	uv run --group localstack pytest tests/localstack/integration/ -v -m "not slow" --tb=short -ra

# Requires the Prow/nested-Podman environment, LOCALSTACK_AUTH_TOKEN, and ARTIFACT_DIR.
test-localstack-ci: ## Run the LocalStack CI entrypoint (includes startup and JUnit output)
	exec ./tests/localstack/ci-run.sh

# Lambda container image build
.PHONY: build-lambda-image

build-lambda-image: ## Build the create-investigation Lambda container image locally
	@echo "Building create-investigation Lambda container image..."
	$(MAKE) -C lambda/create-investigation build-image

# Local unit/regression suite. Run sequentially even with make -j: uv commands
# can sync shared environments. LocalStack, image builds, and lint are separate.
test: ## Run Go coverage, Lambda, build-helper, and Bats tests
	@command -v bats >/dev/null 2>&1 || { echo "ERROR: bats is required (macOS: brew install bats-core; Fedora: dnf install bats)"; exit 1; }
	$(MAKE) test-coverage
	$(MAKE) test-lambda
	$(MAKE) test-github-dl
	$(MAKE) test-shell

# Run all independent gates and preserve their logs, including failures.
# LocalStack must already be running; TEST_ALL_ARGS=--require-complete rejects skips.
TEST_ALL_ARGS ?=
test-all: ## All local suites, lint/format, Terraform, and LocalStack checks
	python3 scripts/test_all.py $(TEST_ALL_ARGS)

# Keep quality gates sequential: pre-commit may rewrite files and uv may sync.
check: ## Run tests, strict lint, Staticcheck, and pre-commit (may modify files)
	$(MAKE) test
	$(MAKE) lint
	$(MAKE) staticcheck
	$(MAKE) pre-commit

pre-commit: ## Run all pre-commit hooks (may modify files)
	uv run --group localstack pre-commit run --all-files

test-shell: ## Run shell runtime and LocalStack startup regression tests (no containers)
	@set -eu; \
		test_path="$$PATH"; \
		if [ "$$(uname)" = Darwin ]; then \
			command -v brew >/dev/null 2>&1 || { echo "ERROR: shell tests need Homebrew coreutils and gnu-sed on macOS"; exit 1; }; \
			for formula in coreutils gnu-sed; do \
				prefix=$$(brew --prefix "$$formula"); \
				[ -d "$$prefix/libexec/gnubin" ] || { echo "ERROR: run brew install coreutils gnu-sed"; exit 1; }; \
				test_path="$$prefix/libexec/gnubin:$$test_path"; \
			done; \
		fi; \
		PATH="$$test_path" bats tests/shell/ tests/localstack/ci-run.bats tests/localstack/compose.bats

# Lambda unit testing
.PHONY: test-lambda test-lambda-reap-tasks test-lambda-reap-investigations test-lambda-create-investigation

test-lambda: test-lambda-reap-tasks test-lambda-reap-investigations test-lambda-create-investigation ## Run all Lambda unit tests

test-lambda-reap-tasks: ## Run reap-tasks Lambda unit tests
	@echo "Running reap-tasks unit tests..."
	cd lambda/reap-tasks && uv run --with boto3 python -m unittest test_handler -v

test-lambda-reap-investigations: ## Run reap-investigations Lambda unit tests
	@echo "Running reap-investigations unit tests..."
	cd lambda/reap-investigations && uv run --with boto3 python -m unittest test_handler -v

test-lambda-create-investigation: ## Run create-investigation Lambda unit tests
	@echo "Running create-investigation unit tests..."
	cd lambda/create-investigation && uv run pytest test_handler.py -v

# Build helper unit tests
test-github-dl: ## Run github_dl.py unit tests (venv auto-created in /tmp)
	@echo "Running github_dl unit tests..."
	@set -eu; \
		venv_dir=$$(mktemp -d /tmp/github_dl_test_venv.XXXXXX); \
		trap 'rm -rf "$$venv_dir"' EXIT; \
		python3 -m venv "$$venv_dir"; \
		"$$venv_dir/bin/pip" install --quiet --no-cache-dir requests "PyJWT[crypto]" pytest; \
		cd build; \
		"$$venv_dir/bin/python3" -m pytest test_github_dl.py -v --tb=short

staticcheck: ## Run staticcheck before commits
	@echo "Running staticcheck..."
	@if command -v staticcheck > /dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed. Install with: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
		exit 1; \
	fi

# Go CLI targets
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

test-coverage: ## Run Go unit tests with coverage report
	@echo "Running Go tests with coverage..."
	go test -coverprofile=coverage.out -covermode=atomic ./...
	@echo "Coverage report written to coverage.out"
	@go tool cover -func=coverage.out | tail -1

codecov: test-coverage ## Generate Go coverage and upload to Codecov
	scripts/codecov.sh

fmt: ## Format Go and shell code
	@echo "Formatting Go code..."
	gofmt -w .
	@echo "Formatting shell scripts..."
	@if command -v shfmt > /dev/null 2>&1; then \
		shfmt -w -i 4 entrypoint.sh deploy/regional/examples/; \
	else \
		echo "shfmt not installed, skipping shell formatting"; \
	fi

lint: ## Lint Go code and shell scripts
	@echo "Linting Go code..."
	@if command -v golangci-lint > /dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, running go vet instead"; \
		go vet ./...; \
	fi
	$(MAKE) lint-shell

lint-shell: ## Run strict ShellCheck on entrypoint, examples, and Compose wrapper
	@command -v shellcheck >/dev/null 2>&1 || { echo "ERROR: shellcheck is required"; exit 1; }
	shellcheck entrypoint.sh deploy/regional/examples/*.sh tests/localstack/compose.sh

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
	@echo "Local Test Suite (no LocalStack or AWS required):"
	@echo "  make test-all        - All local checks; requires running LocalStack and Terraform access"
	@echo "  make test            - Go coverage, Lambda, build-helper, and Bats tests"
	@echo "  make test-shell      - Shell runtime and startup regression tests"
	@echo ""
	@echo "Go CLI Targets:"
	@echo "  make build-cli       - Build the rosa-boundary CLI binary (./bin/rosa-boundary)"
	@echo "  make install-cli     - Install CLI to GOBIN (~/go/bin)"
	@echo "  make test-cli        - Run CLI unit tests"
	@echo "  make test-coverage   - Run Go tests with coverage report (coverage.out)"
	@echo "  make codecov         - Generate coverage and upload to Codecov (CI only)"
	@echo ""
	@echo "LocalStack Testing Targets:"
	@echo "  make localstack-up         - Start LocalStack Pro with all services"
	@echo "  make localstack-down       - Stop LocalStack and clean up"
	@echo "  make localstack-logs       - View LocalStack logs"
	@echo "  make test-localstack       - Run all LocalStack integration tests"
	@echo "  make test-localstack-fast  - Run LocalStack tests (skip slow tests)"
	@echo "  make test-localstack-ci    - Run CI entrypoint (requires nested Podman, token, ARTIFACT_DIR)"
	@echo ""
	@echo "Lambda Targets:"
	@echo "  make build-lambda-image                  - Build create-investigation Lambda container image"
	@echo "  make test-lambda                         - Run all Lambda unit tests"
	@echo "  make test-lambda-reap-tasks              - Run reap-tasks unit tests"
	@echo "  make test-lambda-reap-investigations     - Run reap-investigations unit tests"
	@echo "  make test-lambda-create-investigation    - Run create-investigation unit tests"
	@echo ""
	@echo "Build Helper Targets:"
	@echo "  make test-github-dl  - Run github_dl.py unit tests"
	@echo ""
	@echo "Code Quality Targets:"
	@echo "  make check        - Tests, strict lint, Staticcheck, and pre-commit (may modify files)"
	@echo "  make lint-shell   - Strict ShellCheck on entrypoint, examples, and Compose wrapper"
	@echo "  make pre-commit   - All pre-commit hooks (may modify files)"
	@echo "  make fmt          - Format Go code (gofmt) and shell scripts (shfmt)"
	@echo "  make lint         - Lint Go (golangci-lint/go vet) and shell (shellcheck)"
	@echo "  make staticcheck  - Run staticcheck static analysis"
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
