package ocm

import (
	"encoding/json"
	"errors"
)

// Request is the complete access-token-only payload accepted by the helper.
type Request struct {
	AccessToken string `json:"access_token"`
	URL         string `json:"url"`
}

// MarshalRequest creates the bounded in-memory helper request.
func MarshalRequest(accessToken string, environment Environment) ([]byte, error) {
	if accessToken == "" {
		return nil, errors.New("OCM authentication returned no access token")
	}
	if environment.URL != ProductionURL && environment.URL != StagingURL && environment.URL != IntegrationURL {
		return nil, errors.New("OCM environment is not approved")
	}
	return json.Marshal(Request{AccessToken: accessToken, URL: environment.URL})
}
