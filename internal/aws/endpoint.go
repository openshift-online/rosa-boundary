//go:build !localstack

package aws

// integrationEndpoint leaves normal builds on the AWS SDK's standard endpoints.
func integrationEndpoint() *string { return nil }
