# Local helpers only; account state is separate from every regional state.
SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

REPO_ROOT := $(abspath ../..)
ENV_FILE ?= $(REPO_ROOT)/.env
TF_ARGS ?=

.PHONY: help init fmt validate test plan apply
help:
	@echo "ROSA Boundary Account Infrastructure (one state per AWS account)"
	echo "Targets: init, fmt, validate, test, plan, apply"

init:
	terraform init $(TF_ARGS)

fmt:
	terraform fmt -recursive

validate:
	terraform validate

test:
	terraform test $(TF_ARGS)

plan:
	@if [[ -f "$(ENV_FILE)" ]]; then set -a; source "$(ENV_FILE)"; set +a; fi
	terraform plan $(TF_ARGS)

apply:
	@if [[ -f "$(ENV_FILE)" ]]; then set -a; source "$(ENV_FILE)"; set +a; fi
	terraform apply $(TF_ARGS)
