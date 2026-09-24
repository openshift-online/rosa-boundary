"""
Integration tests for investigation reaper Lambda.

LocalStack's Docker executor cannot reliably invoke Lambda functions in this
environment. All reaper Lambda invocation tests have been removed in favor of:

- 60+ comprehensive unit tests in lambda/reap-investigations/test_handler.py
  (moto-based mocks covering all handler logic)
- 6 directory-focused integration tests in test_reap_investigations_directory.py
  (testing EFS directory operations without Lambda invocation)

Production Lambda functionality will be validated in actual AWS staging/production
environments where LocalStack limitations don't apply.
"""
