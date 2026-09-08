package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGetTokenReturnsValidCachedToken(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cachedToken := testJWT(t, time.Now().Add(10*time.Minute))
	if err := SaveToken(cachedToken); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}

	browserCalled := false
	deps := oidcDependencies{
		browserOpener: func(string) error {
			browserCalled = true
			return errors.New("browser should not be opened")
		},
	}

	got, err := getTokenWithDeps(context.Background(), PKCEConfig{}, false, deps)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if got != cachedToken {
		t.Errorf("GetToken() = %q, want cached token %q", got, cachedToken)
	}
	if browserCalled {
		t.Error("GetToken() opened the browser despite a valid cached token")
	}
}

func TestGetTokenAuthenticatesAndCachesToken(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	cachedToken := testJWT(t, time.Now().Add(10*time.Minute))
	if err := SaveToken(cachedToken); err != nil {
		t.Fatalf("SaveToken() error = %v", err)
	}
	freshToken := testJWT(t, time.Now().Add(20*time.Minute))
	flowCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var authURL string
	var callbackState string
	deps := oidcDependencies{
		browserOpener: func(gotURL string) error {
			authURL = gotURL
			return nil
		},
		callbackServerStarter: func(_ context.Context, expectedState string) (string, error) {
			callbackState = expectedState
			return "authorization-code", nil
		},
	}

	var exchangeArgs struct {
		ctx           context.Context
		tokenEndpoint string
		clientID      string
		redirectURI   string
		code          string
		verifier      string
	}
	deps.codeExchanger = func(ctx context.Context, tokenEndpoint, clientID, redirectURI, code, verifier string) (string, error) {
		exchangeArgs = struct {
			ctx           context.Context
			tokenEndpoint string
			clientID      string
			redirectURI   string
			code          string
			verifier      string
		}{ctx, tokenEndpoint, clientID, redirectURI, code, verifier}
		return freshToken, nil
	}

	got, err := getTokenWithDeps(flowCtx, PKCEConfig{
		KeycloakURL: "https://keycloak.example/",
		Realm:       "test",
		ClientID:    "client-id",
	}, true, deps)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if got != freshToken {
		t.Errorf("GetToken() = %q, want fresh token %q", got, freshToken)
	}
	if exchangeArgs.ctx != flowCtx {
		t.Error("token exchange did not receive the flow context")
	}

	parsedAuthURL, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("Parse(authURL) error = %v", err)
	}
	if got, want := parsedAuthURL.Path, "/realms/test/protocol/openid-connect/auth"; got != want {
		t.Errorf("authorization endpoint path = %q, want %q", got, want)
	}
	query := parsedAuthURL.Query()
	for key, want := range map[string]string{
		"client_id":             "client-id",
		"response_type":         "code",
		"redirect_uri":          "http://localhost:8400/callback",
		"scope":                 "openid profile email",
		"code_challenge_method": "S256",
	} {
		if got := query.Get(key); got != want {
			t.Errorf("authorization query %s = %q, want %q", key, got, want)
		}
	}
	if query.Get("state") != callbackState {
		t.Errorf("authorization state = %q, want callback state %q", query.Get("state"), callbackState)
	}
	if query.Get("code_challenge") == "" {
		t.Error("authorization query has empty code_challenge")
	}

	if got, want := exchangeArgs.tokenEndpoint, "https://keycloak.example/realms/test/protocol/openid-connect/token"; got != want {
		t.Errorf("token endpoint = %q, want %q", got, want)
	}
	if got, want := exchangeArgs.clientID, "client-id"; got != want {
		t.Errorf("token exchange client ID = %q, want %q", got, want)
	}
	if got, want := exchangeArgs.redirectURI, "http://localhost:8400/callback"; got != want {
		t.Errorf("token exchange redirect URI = %q, want %q", got, want)
	}
	if got, want := exchangeArgs.code, "authorization-code"; got != want {
		t.Errorf("authorization code = %q, want %q", got, want)
	}
	if exchangeArgs.verifier == "" {
		t.Error("token exchange verifier is empty")
	}

	cachePath := filepath.Join(os.Getenv("XDG_CACHE_HOME"), "rosa-boundary", tokenCacheFile)
	data, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("read token cache: %v", err)
	}
	if got := string(data); got != freshToken {
		t.Errorf("cached token = %q, want %q", got, freshToken)
	}
}

func TestExchangeCodeUsesContextAndFormRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("request method = %q, want POST", r.Method)
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm() error = %v", err)
		}
		if got, want := r.Form.Get("code"), "authorization-code"; got != want {
			t.Errorf("code = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"id_token":"id-token"}`))
	}))
	defer server.Close()

	got, err := exchangeCode(context.Background(), server.URL, "client-id", "http://localhost/callback", "authorization-code", "verifier")
	if err != nil {
		t.Fatalf("exchangeCode() error = %v", err)
	}
	if got != "id-token" {
		t.Errorf("exchangeCode() = %q, want id-token", got)
	}
}

func TestExchangeCodeHonorsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := exchangeCode(ctx, "http://127.0.0.1:1", "client-id", "http://localhost/callback", "authorization-code", "verifier")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("exchangeCode() error = %v, want context canceled", err)
	}
}

func TestGetTokenContinuesAfterBrowserLaunchFailure(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	freshToken := testJWT(t, time.Now().Add(10*time.Minute))
	deps := oidcDependencies{
		callbackServerStarter: func(context.Context, string) (string, error) {
			return "authorization-code", nil
		},
		codeExchanger: func(_ context.Context, _, _, _, code, verifier string) (string, error) {
			if code != "authorization-code" {
				t.Errorf("authorization code = %q, want authorization-code", code)
			}
			if verifier == "" {
				t.Error("token exchange verifier is empty")
			}
			return freshToken, nil
		},
		browserOpener: func(string) error {
			return errors.New("browser launch failed")
		},
	}

	got, err := getTokenWithDeps(context.Background(), PKCEConfig{
		KeycloakURL: "https://keycloak.example",
		Realm:       "test",
		ClientID:    "client-id",
	}, true, deps)
	if err != nil {
		t.Fatalf("GetToken() error = %v", err)
	}
	if got != freshToken {
		t.Errorf("GetToken() = %q, want fresh token %q", got, freshToken)
	}
}

func TestGetTokenReturnsCallbackError(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	exchangeCalled := false
	deps := oidcDependencies{
		callbackServerStarter: func(context.Context, string) (string, error) {
			return "", errors.New("state mismatch (possible CSRF)")
		},
		browserOpener: func(string) error { return nil },
		codeExchanger: func(_ context.Context, _, _, _, _, _ string) (string, error) {
			exchangeCalled = true
			return "unexpected-token", nil
		},
	}

	got, err := getTokenWithDeps(context.Background(), PKCEConfig{
		KeycloakURL: "https://keycloak.example",
		Realm:       "test",
		ClientID:    "client-id",
	}, true, deps)
	if got != "" {
		t.Errorf("GetToken() token = %q, want empty token", got)
	}
	if err == nil || !strings.Contains(err.Error(), "callback failed: state mismatch (possible CSRF)") {
		t.Errorf("GetToken() error = %v, want callback state mismatch", err)
	}
	if exchangeCalled {
		t.Error("GetToken() exchanged a token after callback failure")
	}
}

// testJWT creates an unsigned JWT-shaped token with the requested expiration.
func testJWT(t *testing.T, expiration time.Time) string {
	t.Helper()
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(data)
	}
	return encode(map[string]string{"alg": "none", "typ": "JWT"}) + "." +
		encode(map[string]int64{"exp": expiration.Unix()}) + ".signature"
}
