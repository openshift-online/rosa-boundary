# Makefile for building multi-arch ROSA Boundary container
IMAGE_NAME := rosa-boundary
TAG := latest
FULL_IMAGE := $(IMAGE_NAME):$(TAG)

# Architecture-specific image tags
AMD64_IMAGE := $(IMAGE_NAME):$(TAG)-amd64
ARM64_IMAGE := $(IMAGE_NAME):$(TAG)-arm64

.PHONY: all build build-amd64 build-arm64 manifest clean help

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
	cd lambda/create-investigation && \
		uv run --with-requirements requirements.txt --with-requirements requirements-test.txt \
		pytest test_handler.py -v

staticcheck: ## Run staticcheck before commits
	@echo "Running staticcheck..."
	@if command -v staticcheck > /dev/null 2>&1; then \
		staticcheck ./...; \
	else \
		echo "staticcheck not installed. Install with: go install honnef.co/go/tools/cmd/staticcheck@latest"; \
		exit 1; \
	fi

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
	@echo "Code Quality Targets:"
	@echo "  make staticcheck  - Run staticcheck before commits"
	@echo ""
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Current configuration:"
	@echo "  Image name: $(FULL_IMAGE)"
	@echo "  AMD64 tag:  $(AMD64_IMAGE)"
	@echo "  ARM64 tag:  $(ARM64_IMAGE)"
