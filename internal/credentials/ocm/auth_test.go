package ocm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func TestDeviceVerificationURL(t *testing.T) {
	complete := "https://sso.redhat.com/device?user_code=complete"
	got, err := deviceVerificationURL(&oauth2.DeviceAuthResponse{VerificationURIComplete: complete})
	if err != nil || got != complete {
		t.Fatalf("complete URL = %q, %v", got, err)
	}

	got, err = deviceVerificationURL(&oauth2.DeviceAuthResponse{UserCode: "AB CD"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://sso.redhat.com/device?user_code=AB+CD" {
		t.Fatalf("fallback URL = %q", got)
	}
}

func TestAccessTokenOnlyClearsOAuthTokenSecrets(t *testing.T) {
	oauthToken := &oauth2.Token{AccessToken: "access-canary", RefreshToken: "refresh-canary", Expiry: time.Now().Add(time.Minute)}
	result, err := accessTokenOnly(oauthToken)
	if err != nil {
		t.Fatal(err)
	}
	if result.AccessToken != "access-canary" || oauthToken.AccessToken != "" || oauthToken.RefreshToken != "" {
		t.Fatalf("token references were not reduced: result=%#v oauth=%#v", result, oauthToken)
	}
}

func TestAuthCodeHandlerValidatesStateAndUsesPKCEWithoutLeakingCode(t *testing.T) {
	var tokenForm url.Values
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		tokenForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "access-canary",
			"refresh_token": "refresh-canary",
			"token_type":    "Bearer",
			"expires_in":    900,
		})
	}))
	defer tokenServer.Close()

	config := &oauth2.Config{ClientID: ClientID, RedirectURL: RedirectURL, Endpoint: oauth2.Endpoint{TokenURL: tokenServer.URL}}
	results := make(chan authCodeResult, 1)
	var debugLog strings.Builder
	debug := func(format string, args ...any) {
		_, _ = fmt.Fprintf(&debugLog, format+"\n", args...)
	}
	handler := authCodeHandler(context.Background(), config, "expected-state", "pkce-verifier", results, debug)

	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodGet, "/oauth/callback?state=wrong&code=authorization-code-canary", nil))
	if bad.Code != http.StatusBadRequest || len(results) != 0 {
		t.Fatalf("invalid state was not rejected: status=%d results=%d", bad.Code, len(results))
	}

	good := httptest.NewRecorder()
	handler.ServeHTTP(good, httptest.NewRequest(http.MethodGet, "/oauth/callback?state=expected-state&code=authorization-code-canary", nil))
	result := <-results
	if result.err != nil || result.token.AccessToken != "access-canary" {
		t.Fatalf("valid callback failed: %#v", result)
	}
	if tokenForm.Get("code_verifier") != "pkce-verifier" || tokenForm.Get("code") != "authorization-code-canary" {
		t.Fatalf("token request did not use code and PKCE: %#v", tokenForm)
	}
	if strings.Contains(good.Body.String(), "authorization-code-canary") || strings.Contains(good.Body.String(), "access-canary") {
		t.Fatal("callback response leaked OAuth material")
	}
	if !strings.Contains(debugLog.String(), "state validated") || !strings.Contains(debugLog.String(), "exchange completed") {
		t.Fatalf("debug log does not identify callback progress: %q", debugLog.String())
	}
	for _, secret := range []string{"authorization-code-canary", "access-canary", "refresh-canary", "pkce-verifier"} {
		if strings.Contains(debugLog.String(), secret) {
			t.Fatalf("debug log leaked OAuth material %q", secret)
		}
	}
}

func TestAuthCodeHandlerSanitizesTokenEndpointErrors(t *testing.T) {
	secretResponse := "raw-token-response-canary"
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, secretResponse)
	}))
	defer tokenServer.Close()

	config := &oauth2.Config{ClientID: ClientID, RedirectURL: RedirectURL, Endpoint: oauth2.Endpoint{TokenURL: tokenServer.URL}}
	results := make(chan authCodeResult, 1)
	handler := authCodeHandler(context.Background(), config, "state", "verifier", results, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/oauth/callback?state=state&code=authorization-code-canary", nil))
	result := <-results
	if result.err == nil {
		t.Fatal("token endpoint failure succeeded")
	}
	if strings.Contains(result.err.Error(), secretResponse) || strings.Contains(result.err.Error(), "authorization-code-canary") {
		t.Fatalf("error leaked OAuth response material: %v", result.err)
	}
}
