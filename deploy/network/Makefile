# Local helpers only; network state is separate from account and every regional state.
SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

REPO_ROOT := $(abspath ../..)

.PHONY: help init fmt validate test plan apply output
help:
	@echo "ROSA Boundary Network Infrastructure (VPC, subnets, NAT, endpoints)"
	echo "Targets: init, fmt, validate, test, plan, apply, output"

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

output:
	terraform output
