# Local helpers only; account state is separate from every regional state.
SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

REPO_ROOT := $(abspath ../..)

.PHONY: help init fmt validate test plan apply
help:
	@echo "ROSA Boundary Account Infrastructure (one state per AWS account)"
	echo "Targets: init, fmt, validate, test, plan, apply"

init:
	terraform init

fmt:
	terraform fmt -recursive

validate:
	terraform validate

test:
	terraform test

plan:
	@if [[ -f "$(REPO_ROOT)/.env" ]]; then set -a; source "$(REPO_ROOT)/.env"; set +a; fi
	terraform plan

apply:
	@if [[ -f "$(REPO_ROOT)/.env" ]]; then set -a; source "$(REPO_ROOT)/.env"; set +a; fi
	terraform apply
