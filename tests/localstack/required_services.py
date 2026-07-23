"""Services LocalStack must report as 'available' or 'running' before tests run.
Consumed by conftest.py (localstack_available fixture) and ci-run.sh (readiness poll).
Keep in sync with the SERVICES= env var in ci-run.sh: adding a service here without
adding it to SERVICES will cause the readiness gate to wait forever."""

REQUIRED = ['s3', 'iam', 'ecs', 'efs', 'kms', 'ssm', 'ec2', 'sqs']
