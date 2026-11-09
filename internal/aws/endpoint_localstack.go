//go:build localstack

package aws

import (
	"net/url"
	"os"
)

// integrationEndpoint is compiled only into explicitly tagged integration builds.
// Fail closed: these integration clients must not fall back to real AWS endpoints.
func integrationEndpoint() *string {
	endpoint := os.Getenv("LOCALSTACK_ENDPOINT")
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
		panic("localstack build requires a loopback HTTP LOCALSTACK_ENDPOINT")
	}
	return &endpoint
}
