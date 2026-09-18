package ocm

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalRequestContainsOnlyAccessTokenAndURL(t *testing.T) {
	token := "access-token-canary"
	encoded, err := MarshalRequest(token, Environment{Name: "production", URL: ProductionURL})
	if err != nil {
		t.Fatal(err)
	}
	var request map[string]any
	if err := json.Unmarshal(encoded, &request); err != nil {
		t.Fatal(err)
	}
	if len(request) != 2 || request["access_token"] != token || request["url"] != ProductionURL {
		t.Fatalf("unexpected request shape: %#v", request)
	}
	for key := range request {
		if strings.Contains(key, "refresh") || strings.Contains(key, "offline") {
			t.Fatalf("request contains forbidden key %q", key)
		}
	}
}

func TestMarshalRequestRejectsMissingTokenAndUnapprovedURL(t *testing.T) {
	if _, err := MarshalRequest("", Environment{URL: ProductionURL}); err == nil {
		t.Fatal("missing token was accepted")
	}
	if _, err := MarshalRequest("token", Environment{URL: "https://attacker.example"}); err == nil {
		t.Fatal("unapproved URL was accepted")
	}
}
