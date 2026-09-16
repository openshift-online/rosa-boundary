package ocm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/skratchdot/open-golang/open"
	"golang.org/x/oauth2"
)

// Flow selects the interactive OAuth flow used to issue a fresh token.
type Flow string

const (
	FlowAuthCode Flow = "auth-code"
	FlowDevice   Flow = "device"
)

// Token contains only the short-lived material needed for transfer.
type Token struct {
	AccessToken string
	Expiry      time.Time
}

// Authenticator owns the local side effects used by OCM OAuth.
type Authenticator struct {
	HTTPClient  *http.Client
	OpenBrowser func(string) error
	Listen      func(network, address string) (net.Listener, error)
	Status      func(format string, args ...any)
	Debug       func(format string, args ...any)
	Timeout     time.Duration
}

// NewAuthenticator returns an authenticator using verified default TLS.
func NewAuthenticator(status func(string, ...any)) *Authenticator {
	return &Authenticator{
		HTTPClient:  http.DefaultClient,
		OpenBrowser: openBrowser,
		Listen:      net.Listen,
		Status:      status,
		Timeout:     5 * time.Minute,
	}
}

// Acquire obtains a newly issued access token without reading or writing a cache.
func (a *Authenticator) Acquire(ctx context.Context, flow Flow) (Token, error) {
	switch flow {
	case FlowAuthCode:
		return a.acquireAuthCode(ctx)
	case FlowDevice:
		return a.acquireDevice(ctx)
	default:
		return Token{}, fmt.Errorf("unsupported OCM authentication flow %q; use auth-code or device", flow)
	}
}

func (a *Authenticator) oauthConfig() *oauth2.Config {
	return &oauth2.Config{
		ClientID:    ClientID,
		RedirectURL: RedirectURL,
		Scopes:      []string{"openid"},
		Endpoint: oauth2.Endpoint{
			AuthURL:       AuthURL,
			DeviceAuthURL: DeviceAuthURL,
			TokenURL:      TokenURL,
		},
	}
}

func (a *Authenticator) oauthContext(ctx context.Context) context.Context {
	client := a.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func (a *Authenticator) acquireDevice(ctx context.Context) (Token, error) {
	ctx = a.oauthContext(ctx)
	config := a.oauthConfig()
	verifier := oauth2.GenerateVerifier()
	a.debug("Requesting OCM device authorization")
	device, err := config.DeviceAuth(ctx, oauth2.S256ChallengeOption(verifier), oauth2.VerifierOption(verifier))
	if err != nil {
		a.debug("OCM device authorization request failed")
		return Token{}, errors.New("request OCM device authorization failed")
	}
	a.debug("OCM device authorization received; preparing browser approval")

	verificationURL, err := deviceVerificationURL(device)
	if err != nil {
		return Token{}, err
	}
	a.status("Open this URL to authorize OCM:\n%s", verificationURL)
	if device.VerificationURIComplete == "" {
		a.status("If prompted, enter code: %s", device.UserCode)
	}
	if a.OpenBrowser != nil {
		if err := a.OpenBrowser(verificationURL); err != nil {
			a.status("Could not open a browser automatically; use the URL above")
			a.debug("Automatic browser launch failed")
		} else {
			a.debug("Automatic browser launch started")
		}
	}

	a.debug("Waiting for OCM device authorization approval")
	token, err := config.DeviceAccessToken(ctx, device, oauth2.VerifierOption(verifier))
	if err != nil {
		a.debug("OCM device authorization did not complete successfully")
		return Token{}, errors.New("complete OCM device authorization failed")
	}
	a.debug("OCM device token exchange completed")
	return accessTokenOnly(token)
}

type authCodeResult struct {
	token *oauth2.Token
	err   error
}

func (a *Authenticator) acquireAuthCode(ctx context.Context) (Token, error) {
	// The SDK helper returns a refresh token, so this flow owns the exchange and
	// immediately reduces its response to the short-lived access token.
	listen := a.Listen
	if listen == nil {
		listen = net.Listen
	}
	listener, err := listen("tcp", "127.0.0.1:9998")
	if err != nil {
		return Token{}, fmt.Errorf("listen for OCM callback on 127.0.0.1:9998: %w", err)
	}
	a.debug("OCM callback listener started on 127.0.0.1:9998")

	state, err := randomState()
	if err != nil {
		_ = listener.Close()
		return Token{}, fmt.Errorf("generate OAuth state: %w", err)
	}
	verifier := oauth2.GenerateVerifier()
	config := a.oauthConfig()
	result := make(chan authCodeResult, 1)
	timeout := a.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	callbackCtx, cancelCallback := context.WithTimeout(ctx, timeout)
	defer cancelCallback()
	oauthCtx := a.oauthContext(callbackCtx)

	mux := http.NewServeMux()
	mux.Handle("/oauth/callback", authCodeHandler(oauthCtx, config, state, verifier, result, a.debug))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.debug("OCM callback server stopped unexpectedly")
			sendAuthCodeResult(result, authCodeResult{err: fmt.Errorf("OCM callback server stopped unexpectedly: %w", err)})
		}
	}()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	authorizationURL := config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	a.status("Open this URL to authorize OCM:\n%s", authorizationURL)
	if a.OpenBrowser != nil {
		if err := a.OpenBrowser(authorizationURL); err != nil {
			a.status("Could not open a browser automatically; use the URL above")
			a.debug("Automatic browser launch failed")
		} else {
			a.debug("Automatic browser launch started")
		}
	}

	a.debug("Waiting for OCM authorization callback")
	select {
	case completed := <-result:
		if completed.err != nil {
			return Token{}, completed.err
		}
		a.debug("OCM authorization-code flow completed")
		return accessTokenOnly(completed.token)
	case <-callbackCtx.Done():
		if ctx.Err() != nil {
			a.debug("OCM authorization callback wait canceled")
			return Token{}, ctx.Err()
		}
		a.debug("OCM authorization callback wait timed out")
		return Token{}, errors.New("OCM authorization timed out waiting for callback")
	}
}

func authCodeHandler(ctx context.Context, config *oauth2.Config, expectedState, verifier string, result chan<- authCodeResult, debug func(string, ...any)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			callDebug(debug, "OCM callback rejected an unexpected HTTP method")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		query := request.URL.Query()
		if query.Get("state") != expectedState {
			callDebug(debug, "OCM callback rejected an invalid OAuth state")
			http.Error(w, "invalid OAuth state", http.StatusBadRequest)
			return
		}
		if query.Get("error") != "" {
			callDebug(debug, "OCM authorization callback reported an OAuth error")
			http.Error(w, "authorization was not completed", http.StatusBadRequest)
			sendAuthCodeResult(result, authCodeResult{err: errors.New("OCM authorization failed")})
			return
		}
		code := query.Get("code")
		if code == "" {
			callDebug(debug, "OCM callback did not contain an authorization code")
			http.Error(w, "authorization response did not include a code", http.StatusBadRequest)
			sendAuthCodeResult(result, authCodeResult{err: errors.New("OCM authorization response did not include a code")})
			return
		}

		callDebug(debug, "OCM callback received and state validated; exchanging authorization code")
		token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			callDebug(debug, "OCM authorization-code exchange failed")
			http.Error(w, "authorization exchange failed", http.StatusBadGateway)
			sendAuthCodeResult(result, authCodeResult{err: errors.New("exchange OCM authorization code failed")})
			return
		}
		callDebug(debug, "OCM authorization-code exchange completed")
		_, _ = io.WriteString(w, "Login successful. You may close this window and return to the terminal.")
		sendAuthCodeResult(result, authCodeResult{token: token})
	})
}

func sendAuthCodeResult(result chan<- authCodeResult, value authCodeResult) {
	select {
	case result <- value:
	default:
	}
}

func randomState() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func deviceVerificationURL(device *oauth2.DeviceAuthResponse) (string, error) {
	if device.VerificationURIComplete != "" {
		parsed, err := url.Parse(device.VerificationURIComplete)
		if err != nil || parsed.Scheme == "" || parsed.Host == "" {
			return "", errors.New("OCM device authorization returned an invalid verification URL")
		}
		return parsed.String(), nil
	}
	if device.UserCode == "" {
		return "", errors.New("OCM device authorization returned no user code")
	}
	return ssoBaseURL + "/device?user_code=" + url.QueryEscape(device.UserCode), nil
}

func accessTokenOnly(token *oauth2.Token) (Token, error) {
	if token == nil || token.AccessToken == "" {
		return Token{}, errors.New("OCM authentication returned no access token")
	}
	result := Token{AccessToken: token.AccessToken, Expiry: token.Expiry}
	token.AccessToken = ""
	token.RefreshToken = ""
	return result, nil
}

func (a *Authenticator) status(format string, args ...any) {
	if a.Status != nil {
		a.Status(format, args...)
	}
}

func (a *Authenticator) debug(format string, args ...any) {
	callDebug(a.Debug, format, args...)
}

func callDebug(debug func(string, ...any), format string, args ...any) {
	if debug != nil {
		debug(format, args...)
	}
}

func openBrowser(target string) error {
	return open.Run(target)
}
