package aws

// IntegrationEndpoint is nil in release builds. In explicitly tagged LocalStack
// builds it requires a loopback HTTP endpoint, including for Lambda invocations.
func IntegrationEndpoint() *string { return integrationEndpoint() }
