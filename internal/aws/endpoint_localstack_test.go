//go:build localstack

package aws

import "testing"

func TestIntegrationEndpointLocalOnly(t *testing.T) {
	for _, endpoint := range []string{"http://localhost:4566", "http://127.0.0.1:4566", "http://[::1]:4566"} {
		t.Setenv("LOCALSTACK_ENDPOINT", endpoint)
		if got := integrationEndpoint(); got == nil || *got != endpoint {
			t.Fatalf("expected loopback endpoint %q", endpoint)
		}
	}
}

func TestIntegrationEndpointRejectsFallbackAndRemote(t *testing.T) {
	for _, endpoint := range []string{"", "https://sts.amazonaws.com", "http://remote.invalid:4566", "http://user:password@localhost:4566", "http://localhost:4566?redirect=remote"} {
		t.Run(endpoint, func(t *testing.T) {
			t.Setenv("LOCALSTACK_ENDPOINT", endpoint)
			defer func() {
				if recover() == nil {
					t.Error("test build must reject missing or remote endpoints")
				}
			}()
			integrationEndpoint()
		})
	}
}
