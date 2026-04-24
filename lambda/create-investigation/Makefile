.PHONY: clean build-image run-local test test-unit test-coverage help validate test-localstack test-e2e-localstack

# Variables
CONTAINER_RUNTIME ?= podman
IMAGE_NAME ?= create-investigation-lambda
IMAGE_TAG ?= latest
TERRAFORM_DIR = ../../deploy/regional

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

clean: ## Remove build artifacts
	@echo "Cleaning build artifacts..."
	rm -rf ./__pycache__
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	@echo "Clean complete"

build-image: ## Build Lambda container image
	@echo "Building Lambda container image..."
	$(CONTAINER_RUNTIME) build --platform linux/amd64 \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-f Containerfile .
	@echo "Image built: $(IMAGE_NAME):$(IMAGE_TAG)"

run-local: build-image ## Build and run Lambda locally with RIE
	@echo "Starting Lambda locally on port 9000..."
	@echo "Test with: curl -XPOST http://localhost:9000/2015-03-31/functions/function/invocations -d '{}'"
	$(CONTAINER_RUNTIME) run --rm -p 9000:8080 $(IMAGE_NAME):$(IMAGE_TAG)

test-unit: ## Run unit tests with pytest
	@echo "Running unit tests..."
	uv run pytest test_handler.py -v

test-coverage: ## Run unit tests with coverage report
	@echo "Running unit tests with coverage..."
	uv run pytest test_handler.py -v --cov=handler --cov-report=term-missing --cov-report=html
	@echo ""
	@echo "HTML coverage report generated in htmlcov/index.html"

test: test-unit ## Alias for test-unit

validate: ## Validate handler syntax
	@echo "Validating Python syntax..."
	python3 -m py_compile handler.py
	@echo "Syntax valid"

test-localstack: ## Run Lambda tests against LocalStack
	@echo "Ensure LocalStack is running: make localstack-up (from project root)"
	uv run pytest ../../tests/localstack/integration/test_lambda_handler.py -v

test-e2e-localstack: ## Run full E2E test against LocalStack
	uv run pytest ../../tests/localstack/integration/test_full_workflow.py -v
