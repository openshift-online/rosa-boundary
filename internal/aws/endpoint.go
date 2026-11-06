//go:build !localstack

package aws

// integrationEndpoint leaves normal builds on the AWS SDK's standard endpoints.
func integrationEndpoint() *string { return nil }

// AWS supports partial task-definition family prefixes server-side.
func taskDefinitionFamilyPrefix(family string) *string { return &family }
