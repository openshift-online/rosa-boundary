package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/authstatus"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

// PKCEConfig holds OIDC/Keycloak configuration for the PKCE flow.
type PKCEConfig struct {
	KeycloakURL string
	Realm       string
	ClientID    string
	RedirectURI string
}

// tokenResponse is the JSON structure returned by the Keycloak token endpoint.
type tokenResponse struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// oidcDependencies contains the side-effecting operations used by the PKCE flow.
// Keeping them explicit allows orchestration tests to remain network-free.
type oidcDependencies struct {
	browserOpener         func(string) error
	callbackServerStarter func(context.Context, string) (string, error)
	codeExchanger         func(context.Context, string, string, string, string, string) (string, error)
}

// Options selects the fresh ID-token flow and the invocation's status stream.
// An absent Reporter preserves the original text-mode behavior.
type Options struct {
	UseDeviceCode bool
	Reporter      *authstatus.Reporter
	// httpClient and wait are injectable only from auth tests; production uses
	// bounded HTTP requests and context-aware polling.
	httpClient *http.Client
	wait       func(context.Context, time.Duration) error
}

// GetToken obtains an OIDC ID token using the PKCE flow.
// It checks the cache first (unless force is true), then opens the browser.
func GetToken(ctx context.Context, cfg PKCEConfig, force bool) (string, error) {
	return GetTokenWithOptions(ctx, cfg, force, Options{})
}

// GetTokenWithOptions shares cache and status reporting across browser and device flows.
func GetTokenWithOptions(ctx context.Context, cfg PKCEConfig, force bool, opts Options) (string, error) {
	return getTokenWithOptionsAndDeps(ctx, cfg, force, opts, oidcDependencies{
		browserOpener:         openBrowser,
		callbackServerStarter: startCallbackServer,
		codeExchanger:         exchangeCode,
	})
}

// getTokenWithDeps runs the PKCE flow with explicitly supplied side-effecting operations.
func getTokenWithDeps(ctx context.Context, cfg PKCEConfig, force bool, deps oidcDependencies) (string, error) {
	return getTokenWithOptionsAndDeps(ctx, cfg, force, Options{}, deps)
}

func getTokenWithOptionsAndDeps(ctx context.Context, cfg PKCEConfig, force bool, opts Options, deps oidcDependencies) (string, error) {
	if !force {
		cached, err := CachedTokenForConfig(cfg)
		if err == nil && cached != "" {
			if err := opts.Reporter.Emit("boundary", "authenticated", map[string]any{"source": "cache"}); err != nil {
				return "", err
			}
			return cached, nil
		}
	}
	var token string
	var err error
	source := "browser"
	if opts.UseDeviceCode {
		source = "device"
		token, err = acquireDeviceToken(ctx, cfg, opts)
	} else {
		token, err = acquireBrowserToken(ctx, cfg, deps)
	}
	if err != nil {
		if writeErr := opts.Reporter.Failure("boundary", err); writeErr != nil {
			return "", fmt.Errorf("authentication status write failed: %w", writeErr)
		}
		return "", err
	}
	expiration, expiryErr := parseTokenExpiration(token)
	if expiryErr != nil || !expiration.After(time.Now().Add(expirationBuffer)) {
		err = &deviceError{reason: "invalid_response", text: "OIDC provider returned an invalid or expired ID token"}
		if writeErr := opts.Reporter.Failure("boundary", err); writeErr != nil {
			return "", fmt.Errorf("authentication status write failed: %w", writeErr)
		}
		return "", err
	}
	if err := SaveTokenForConfig(token, cfg); err != nil {
		output.Warning("could not cache token: %v", err)
	}
	if err := opts.Reporter.Emit("boundary", "authenticated", map[string]any{"source": source}); err != nil {
		return "", err
	}
	return token, nil
}

func acquireBrowserToken(ctx context.Context, cfg PKCEConfig, deps oidcDependencies) (string, error) {

	if err := output.Debug("No cached token, authenticating..."); err != nil {
		return "", fmt.Errorf("debug output failed: %w", err)
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", fmt.Errorf("cannot generate PKCE parameters: %w", err)
	}

	state, err := generateState()
	if err != nil {
		return "", fmt.Errorf("cannot generate state: %w", err)
	}

	redirectURI := cfg.RedirectURI
	if redirectURI == "" {
		redirectURI = "http://localhost:" + callbackPort + "/callback"
	}

	issuerURL := strings.TrimRight(cfg.KeycloakURL, "/") + "/realms/" + cfg.Realm
	authEndpoint := issuerURL + "/protocol/openid-connect/auth"
	tokenEndpoint := issuerURL + "/protocol/openid-connect/token"

	authURL := buildAuthURL(authEndpoint, cfg.ClientID, redirectURI, state, challenge)

	if err := output.Debug("Starting local callback server on port %s...", callbackPort); err != nil {
		return "", fmt.Errorf("debug output failed: %w", err)
	}

	// Start the callback server before opening the browser so it is already
	// listening when the redirect arrives. The goroutine cleans up via the
	// 120-second context timeout if no callback is received.
	callbackCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	codeCh := make(chan callbackResult, 1)
	go func() {
		code, err := deps.callbackServerStarter(callbackCtx, state)
		codeCh <- callbackResult{code: code, err: err}
	}()

	if err := deps.browserOpener(authURL); err != nil {
		output.Status("Could not open browser automatically. Please visit:\n%s", authURL)
	} else {
		if err := output.Debug("Opened browser for authentication. If it fails, visit:\n%s", authURL); err != nil {
			return "", fmt.Errorf("debug output failed: %w", err)
		}
	}

	result := <-codeCh
	code, err := result.code, result.err
	if err != nil {
		return "", fmt.Errorf("callback failed: %w", err)
	}

	if err := output.Debug("Authorization code received, exchanging for token..."); err != nil {
		return "", fmt.Errorf("debug output failed: %w", err)
	}

	token, err := deps.codeExchanger(ctx, tokenEndpoint, cfg.ClientID, redirectURI, code, verifier)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}

	if err := output.Debug("ID token obtained successfully"); err != nil {
		output.Warning("could not write debug output: %v", err)
	}
	return token, nil
}

// generatePKCE creates a code verifier and its S256 challenge.
func generatePKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)

	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

// generateState creates a random state string for CSRF protection.
func generateState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// buildAuthURL constructs the Keycloak authorization URL with PKCE parameters.
func buildAuthURL(authEndpoint, clientID, redirectURI, state, challenge string) string {
	params := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return authEndpoint + "?" + params.Encode()
}

// exchangeCode calls the Keycloak token endpoint to exchange an authorization code.
func exchangeCode(ctx context.Context, tokenEndpoint, clientID, redirectURI, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("cannot create HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned HTTP %d", resp.StatusCode)
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("cannot decode token response")
	}

	if tr.Error != "" {
		return "", fmt.Errorf("token exchange rejected by provider")
	}

	if tr.IDToken == "" {
		return "", fmt.Errorf("no id_token in response (check OIDC client configuration)")
	}

	return tr.IDToken, nil
}

// openBrowser opens the given URL in the user's default browser.
func openBrowser(urlStr string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", urlStr)
	case "linux":
		cmd = exec.Command("xdg-open", urlStr)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", urlStr)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Run()
}
