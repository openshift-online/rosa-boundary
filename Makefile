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

# Lambda container images
CONTAINER_RUNTIME ?= podman
LAMBDA_CREATE_IMAGE := create-investigation-lambda
LAMBDA_REAP_IMAGE := reap-tasks-lambda
LAMBDA_TAG ?= latest
AWS_ACCOUNT_ID ?= $(shell aws sts get-caller-identity --query Account --output text 2>/dev/null)
AWS_REGION ?= $(shell aws configure get region 2>/dev/null || echo us-east-2)
ECR_REGISTRY = $(AWS_ACCOUNT_ID).dkr.ecr.$(AWS_REGION).amazonaws.com

.PHONY: all build build-amd64 build-arm64 manifest clean help \
        build-cli install-cli test-cli fmt lint \
        validate-findings convert-sarif upload-sarif \
        build-lambda-images push-lambda-images login-ecr

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

# Lambda container image targets
build-lambda-images: ## Build Lambda container images
	@echo "Building create-investigation Lambda image..."
	$(CONTAINER_RUNTIME) build --platform linux/amd64 \
		-t $(LAMBDA_CREATE_IMAGE):$(LAMBDA_TAG) \
		-f lambda/create-investigation/Containerfile \
		lambda/create-investigation/
	@echo "Building reap-tasks Lambda image..."
	$(CONTAINER_RUNTIME) build --platform linux/amd64 \
		-t $(LAMBDA_REAP_IMAGE):$(LAMBDA_TAG) \
		-f lambda/reap-tasks/Containerfile \
		lambda/reap-tasks/

login-ecr: ## Authenticate container runtime with ECR
	aws ecr get-login-password --region $(AWS_REGION) | \
		$(CONTAINER_RUNTIME) login --username AWS --password-stdin $(ECR_REGISTRY)

push-lambda-images: build-lambda-images login-ecr ## Build and push Lambda images to ECR
	@STAGE=$${TF_VAR_stage:-dev}; \
	CREATE_REPO=$(ECR_REGISTRY)/rosa-boundary-$$STAGE-create-investigation; \
	REAP_REPO=$(ECR_REGISTRY)/rosa-boundary-$$STAGE-reap-tasks; \
	echo "Pushing create-investigation image..."; \
	$(CONTAINER_RUNTIME) tag $(LAMBDA_CREATE_IMAGE):$(LAMBDA_TAG) $$CREATE_REPO:$(LAMBDA_TAG); \
	$(CONTAINER_RUNTIME) push $$CREATE_REPO:$(LAMBDA_TAG); \
	echo "Pushing reap-tasks image..."; \
	$(CONTAINER_RUNTIME) tag $(LAMBDA_REAP_IMAGE):$(LAMBDA_TAG) $$REAP_REPO:$(LAMBDA_TAG); \
	$(CONTAINER_RUNTIME) push $$REAP_REPO:$(LAMBDA_TAG); \
	echo "Lambda images pushed"

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
	@echo "Linting shell scripts..."
	@if command -v shellcheck > /dev/null 2>&1; then \
		shellcheck deploy/regional/examples/*.sh entrypoint.sh 2>/dev/null || true; \
	else \
		echo "shellcheck not installed, skipping shell linting"; \
	fi

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
	@echo "Go CLI Targets:"
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
	@echo "Lambda Targets:"
	@echo "  make build-lambda-images              - Build Lambda container images"
	@echo "  make push-lambda-images               - Build and push Lambda images to ECR"
	@echo "  make login-ecr                        - Authenticate with ECR"
	@echo "  make test-lambda                      - Run all Lambda unit tests"
	@echo "  make test-lambda-reap-tasks           - Run reap-tasks unit tests"
	@echo "  make test-lambda-create-investigation - Run create-investigation unit tests"
	@echo ""
	@echo "Code Quality Targets:"
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
