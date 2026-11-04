//go:build !localstack

package aws

import "testing"

func TestIntegrationEndpointDisabledInNormalBuild(t *testing.T) {
	t.Setenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")
	t.Setenv("AWS_ENDPOINT_URL", "http://localhost:4566")
	if integrationEndpoint() != nil {
		t.Fatal("normal builds must retain standard AWS endpoint selection")
	}
}
