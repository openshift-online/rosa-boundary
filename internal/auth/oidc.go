package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
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

// GetToken obtains an OIDC ID token using the PKCE flow.
// It checks the cache first (unless force is true), then opens the browser.
func GetToken(ctx context.Context, cfg PKCEConfig, force bool) (string, error) {
	if !force {
		cached, err := CachedToken()
		if err == nil && cached != "" {
			return cached, nil
		}
	}

	fmt.Fprintln(os.Stderr, "No cached token, authenticating...")

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

	fmt.Fprintf(os.Stderr, "Starting local callback server on port %s...\n", callbackPort)
	fmt.Fprintln(os.Stderr, "Opening browser for authentication...")

	if err := openBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "Could not open browser automatically.\nPlease open the following URL:\n%s\n", authURL)
	}

	callbackCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()

	code, err := startCallbackServer(callbackCtx, state)
	if err != nil {
		return "", fmt.Errorf("callback failed: %w", err)
	}

	fmt.Fprintln(os.Stderr, "Authorization code received, exchanging for token...")

	token, err := exchangeCode(tokenEndpoint, cfg.ClientID, redirectURI, code, verifier)
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}

	if err := SaveToken(token); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not cache token: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, "ID token obtained successfully")
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
func exchangeCode(tokenEndpoint, clientID, redirectURI, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}

	resp, err := http.PostForm(tokenEndpoint, form)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("cannot decode token response: %w", err)
	}

	if tr.Error != "" {
		return "", fmt.Errorf("%s: %s", tr.Error, tr.ErrorDesc)
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
	return cmd.Start()
}
