# Terraform deployment for ROSA Boundary regional infrastructure
#
# This Makefile sources .env from the repository root and passes variables
# to Terraform using TF_VAR_ environment variable prefix.

SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c

# Find repository root (two levels up from this Makefile)
REPO_ROOT := $(shell cd ../.. && pwd)
ENV_FILE := $(REPO_ROOT)/.env

# Check if .env exists
ifeq ($(wildcard $(ENV_FILE)),)
    $(warning .env file not found at $(ENV_FILE))
    $(warning Please create .env with required variables (see .env.example if available))
endif

# Source .env and export Terraform variables
# Terraform reads TF_VAR_<name> environment variables automatically
export TF_VAR_keycloak_issuer_url        := $(shell source $(ENV_FILE) 2>/dev/null && echo $$KEYCLOAK_ISSUER_URL)
export TF_VAR_stage_keycloak_issuer_url  := $(shell source $(ENV_FILE) 2>/dev/null && echo $$STAGE_KEYCLOAK_ISSUER_URL)
export TF_VAR_stage_oidc_client_id       := $(shell source $(ENV_FILE) 2>/dev/null && echo $$STAGE_OIDC_CLIENT_ID)
export TF_VAR_stage_keycloak_thumbprint  := $(shell source $(ENV_FILE) 2>/dev/null && echo $$STAGE_KEYCLOAK_THUMBPRINT)
export TF_VAR_abac_tag_key               := $(shell source $(ENV_FILE) 2>/dev/null && echo $${TF_VAR_abac_tag_key:-username})
export TF_VAR_enable_kube_proxy          := $(shell source $(ENV_FILE) 2>/dev/null && echo $${TF_VAR_enable_kube_proxy:-true})

.PHONY: help
help:
	@echo "ROSA Boundary Regional Infrastructure"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  init          - Initialize Terraform"
	@echo "  plan          - Show Terraform execution plan"
	@echo "  apply         - Build Lambda deps, then apply Terraform changes"
	@echo "  destroy       - Destroy all infrastructure"
	@echo "  build-lambda  - Build Lambda dependencies (required before apply)"
	@echo "  lambda        - Update Lambda function only"
	@echo "  show-env      - Display environment variables from .env"
	@echo ""
	@echo "Environment variables are sourced from $(ENV_FILE)"

.PHONY: show-env
show-env:
	@echo "Environment Configuration:"
	@echo "  REPO_ROOT: $(REPO_ROOT)"
	@echo "  ENV_FILE: $(ENV_FILE)"
	@echo ""
	@echo "Terraform Variables:"
	@source $(ENV_FILE) && \
	echo "  TF_VAR_keycloak_issuer_url:       $$KEYCLOAK_ISSUER_URL" && \
	echo "  TF_VAR_stage_keycloak_issuer_url: $$STAGE_KEYCLOAK_ISSUER_URL" && \
	echo "  TF_VAR_stage_oidc_client_id:      $$STAGE_OIDC_CLIENT_ID" && \
	echo "  TF_VAR_abac_tag_key:              $${TF_VAR_abac_tag_key:-username}"

.PHONY: init
init:
	@echo "Initializing Terraform..."
	terraform init

.PHONY: plan
plan:
	@echo "Planning Terraform changes..."
	@source $(ENV_FILE) && \
	export TF_VAR_keycloak_issuer_url="$$KEYCLOAK_ISSUER_URL" && \
	terraform plan

.PHONY: build-lambda
build-lambda: ## Build Lambda dependencies (required before apply)
	@echo "Building Lambda dependencies..."
	@cd ../../lambda/create-investigation && make build

.PHONY: apply
apply: build-lambda
	@echo "Applying Terraform changes..."
	@source $(ENV_FILE) && \
	export TF_VAR_keycloak_issuer_url="$$KEYCLOAK_ISSUER_URL" && \
	terraform apply

.PHONY: destroy
destroy:
	@echo "WARNING: This will destroy all infrastructure!"
	@read -p "Are you sure? Type 'yes' to continue: " confirm && \
	if [ "$$confirm" = "yes" ]; then \
		source $(ENV_FILE) && \
		export TF_VAR_keycloak_issuer_url="$$KEYCLOAK_ISSUER_URL" && \
		terraform destroy; \
	else \
		echo "Cancelled."; \
	fi

.PHONY: lambda
lambda: build-lambda  ## Update Lambda function only
	@echo "Deploying Lambda function..."
	@source $(ENV_FILE) && \
	export TF_VAR_keycloak_issuer_url="$$KEYCLOAK_ISSUER_URL" && \
	terraform apply -target=aws_lambda_function.create_investigation -auto-approve
