.PHONY: clean deps build test test-unit test-coverage help deploy package install-test-deps venv clean-venv

# Variables
CONTAINER_RUNTIME ?= podman
LAMBDA_RUNTIME = public.ecr.aws/lambda/python:3.11
FUNCTION_DIR = $(shell pwd)
REQUIREMENTS = requirements.txt
REQUIREMENTS_TEST = requirements-test.txt
TERRAFORM_DIR = ../../deploy/regional
ZIP_FILE = /tmp/lambda-create-investigation.zip
VENV = .venv
PYTHON = $(VENV)/bin/python
PIP = $(VENV)/bin/pip
PYTEST = $(VENV)/bin/pytest

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

venv: ## Create Python virtual environment
	@if [ ! -d "$(VENV)" ]; then \
		echo "Creating virtual environment..."; \
		uv venv $(VENV); \
		echo "Virtual environment created at $(VENV)"; \
	else \
		echo "Virtual environment already exists at $(VENV)"; \
	fi

clean-venv: ## Remove virtual environment
	@echo "Removing virtual environment..."
	rm -rf $(VENV)
	@echo "Virtual environment removed"

clean: ## Remove build artifacts and dependencies
	@echo "Cleaning build artifacts..."
	rm -rf ./__pycache__
	rm -rf ./bin
	rm -rf ./boto*
	rm -rf ./certifi*
	rm -rf ./cffi*
	rm -rf ./charset_normalizer*
	rm -rf ./cryptography*
	rm -rf ./dateutil*
	rm -rf ./idna*
	rm -rf ./jmespath*
	rm -rf ./jwt*
	rm -rf ./pycparser*
	rm -rf ./python_dateutil*
	rm -rf ./PyJWT*
	rm -rf ./requests*
	rm -rf ./s3transfer*
	rm -rf ./six*
	rm -rf ./urllib3*
	rm -rf ./*.dist-info
	rm -rf ./*.so
	rm -rf ./package
	rm -rf .pytest_cache
	rm -rf htmlcov
	rm -rf .coverage
	@echo "Clean complete"

deps: clean ## Install Lambda dependencies using container runtime (Linux-compatible)
	@echo "Installing Lambda dependencies using AWS Lambda container image (x86_64)..."
	@echo "Using container runtime: $(CONTAINER_RUNTIME)"
	$(CONTAINER_RUNTIME) run --rm \
		--platform linux/amd64 \
		--entrypoint "" \
		-v "$(FUNCTION_DIR)":/var/task:Z \
		$(LAMBDA_RUNTIME) \
		pip install -t /var/task -r /var/task/$(REQUIREMENTS) --no-cache-dir
	@echo "Dependencies installed"

deps-local: clean ## Install dependencies locally using uv (for local testing only - not Lambda compatible on macOS)
	@echo "Installing dependencies locally with uv (not Lambda-compatible)..."
	uv pip install --system -t . -r $(REQUIREMENTS)
	@echo "Local dependencies installed"

build: deps ## Build Lambda deployment package (install deps + verify)
	@echo "Verifying Lambda package..."
	@test -f handler.py || (echo "Error: handler.py not found" && exit 1)
	@test -d jwt || (echo "Error: jwt module not found - run 'make deps' first" && exit 1)
	@test -d cryptography || (echo "Error: cryptography module not found - run 'make deps' first" && exit 1)
	@echo "Lambda package ready for deployment"
	@echo "Files in package:"
	@ls -lh | grep -E "handler|jwt|crypto|requests" | awk '{print "  " $$9 " (" $$5 ")"}'

install-test-deps: venv ## Install test dependencies in virtual environment
	@echo "Installing test dependencies with uv..."
	@uv pip install -r $(REQUIREMENTS_TEST)
	@echo "Installing runtime dependencies for testing..."
	@uv pip install -r $(REQUIREMENTS)
	@echo "Test dependencies installed"

test-unit: install-test-deps ## Run unit tests with pytest
	@echo "Running unit tests..."
	PYTHONPATH=. $(PYTEST) test_handler.py -v

test-coverage: install-test-deps ## Run unit tests with coverage report
	@echo "Running unit tests with coverage..."
	PYTHONPATH=. $(PYTEST) test_handler.py -v --cov=handler --cov-report=term-missing --cov-report=html
	@echo ""
	@echo "HTML coverage report generated in htmlcov/index.html"

test: test-unit ## Alias for test-unit

test-local: ## Test handler imports locally (requires deps-local)
	@echo "Testing Lambda handler locally..."
	python3 -c "import handler; print('Handler imports successfully')"

validate: ## Validate handler syntax
	@echo "Validating Python syntax..."
	python3 -m py_compile handler.py
	@echo "Syntax valid"

package: build ## Create Lambda deployment zip package
	@echo "Creating Lambda deployment package..."
	@rm -f $(ZIP_FILE)
	@zip -q -r $(ZIP_FILE) . \
		-x "*.pyc" \
		-x "__pycache__/*" \
		-x ".git/*" \
		-x "Makefile" \
		-x "README.md" \
		-x "*.md" \
		-x "test_*.py" \
		-x "*requirements-test.txt" \
		-x ".venv/*" \
		-x ".pytest_cache/*" \
		-x "htmlcov/*" \
		-x ".coverage"
	@echo "Package created: $(ZIP_FILE)"
	@ls -lh $(ZIP_FILE)

deploy: package ## Build and deploy Lambda function to AWS
	@echo "Deploying Lambda function..."
	@if [ ! -f "$(TERRAFORM_DIR)/terraform.tfstate" ]; then \
		echo "Error: Terraform state not found. Run 'terraform apply' first."; \
		exit 1; \
	fi
	@FUNCTION_NAME=$$(cd $(TERRAFORM_DIR) && terraform output -raw lambda_function_name 2>/dev/null); \
	if [ -z "$$FUNCTION_NAME" ]; then \
		echo "Error: Could not get Lambda function name from Terraform."; \
		exit 1; \
	fi; \
	echo "Updating Lambda function: $$FUNCTION_NAME"; \
	aws lambda update-function-code \
		--function-name "$$FUNCTION_NAME" \
		--zip-file fileb://$(ZIP_FILE) \
		--output json > /tmp/lambda-update-result.json; \
	echo "✅ Lambda function updated successfully"; \
	echo "Last Modified: $$(jq -r '.LastModified' /tmp/lambda-update-result.json)"; \
	echo "Code Size: $$(jq -r '.CodeSize' /tmp/lambda-update-result.json) bytes"; \
	echo "Waiting for update to complete..."; \
	aws lambda wait function-updated --function-name "$$FUNCTION_NAME"; \
	echo "✅ Lambda function is ready"

test-localstack: install-test-deps ## Run Lambda tests against LocalStack
	@echo "Ensure LocalStack is running: make localstack-up (from project root)"
	PYTHONPATH=. $(PYTEST) ../../tests/localstack/integration/test_lambda_handler.py -v

test-e2e-localstack: install-test-deps ## Run full E2E test against LocalStack
	PYTHONPATH=. $(PYTEST) ../../tests/localstack/integration/test_full_workflow.py -v
