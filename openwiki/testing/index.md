# Files

- [Trusted Actions testing and CI](trusted-actions-testing.md) - Describes the Trusted Actions component's unit, integration, and mock-dependency testing strategy, its Make targets, Postgres test tooling, and its Codecov patch-coverage gate, plus the Konflux Tekton pipelines that build and push its image on PR and push events in this monorepo.
- [Testing and verification](verification.md) - Guide to choosing among ROSA Boundary's Go unit tests, Lambda Python unit tests, Terraform tftest suites, LocalStack integration tests, and shell/bats suites; explains scripts/test_all.py as the aggregating entry point, the LocalStack-vs-Prow CI split, and documented test-boundary limitations.
