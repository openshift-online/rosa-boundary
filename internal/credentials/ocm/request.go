package ocm

import (
	"encoding/json"
	"errors"
)

// Request is the complete access-token-only payload accepted by the helper.
type Request struct {
	AccessToken        string `json:"access_token"`
	URL                string `json:"url"`
	Generation         string `json:"generation,omitempty"`
	ExpectedGeneration string `json:"expected_generation,omitempty"`
}

// MarshalRequest creates the bounded in-memory helper request.
func MarshalRequest(accessToken string, environment Environment) ([]byte, error) {
	return MarshalAttachmentRequest(accessToken, environment, "", "")
}

// MarshalAttachmentRequest adds only non-secret compare-and-swap metadata.
func MarshalAttachmentRequest(accessToken string, environment Environment, generation, expected string) ([]byte, error) {
	if accessToken == "" {
		return nil, errors.New("OCM authentication returned no access token")
	}
	if environment.URL != ProductionURL && environment.URL != StagingURL && environment.URL != IntegrationURL {
		return nil, errors.New("OCM environment is not approved")
	}
	return json.Marshal(Request{AccessToken: accessToken, URL: environment.URL, Generation: generation, ExpectedGeneration: expected})
}
