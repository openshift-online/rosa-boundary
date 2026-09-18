package ocm

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
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
	Debug       func(format string, args ...any) error
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
	if err := a.debug("Requesting OCM device authorization"); err != nil {
		return Token{}, err
	}
	device, err := config.DeviceAuth(ctx, oauth2.S256ChallengeOption(verifier), oauth2.VerifierOption(verifier))
	if err != nil {
		if debugErr := a.debug("OCM device authorization request failed"); debugErr != nil {
			return Token{}, debugErr
		}
		return Token{}, errors.New("request OCM device authorization failed")
	}
	if err := a.debug("OCM device authorization received; preparing browser approval"); err != nil {
		return Token{}, err
	}

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
			if debugErr := a.debug("Automatic browser launch failed"); debugErr != nil {
				return Token{}, debugErr
			}
		} else {
			if debugErr := a.debug("Automatic browser launch started"); debugErr != nil {
				return Token{}, debugErr
			}
		}
	}

	a.status("Waiting for OCM device authorization approval...")
	token, err := config.DeviceAccessToken(ctx, device, oauth2.VerifierOption(verifier))
	if err != nil {
		if debugErr := a.debug("OCM device authorization did not complete successfully"); debugErr != nil {
			return Token{}, debugErr
		}
		return Token{}, errors.New("complete OCM device authorization failed")
	}
	result, err := accessTokenOnly(token)
	if err != nil {
		return Token{}, err
	}
	if err := a.debug("OCM device token exchange completed"); err != nil {
		result.AccessToken = ""
		return Token{}, err
	}
	return result, nil
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
	if err := a.debug("OCM callback listener started on 127.0.0.1:9998"); err != nil {
		_ = listener.Close()
		return Token{}, err
	}

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
			if debugErr := a.debug("OCM callback server stopped unexpectedly"); debugErr != nil {
				sendAuthCodeResult(result, authCodeResult{err: debugErr})
				return
			}
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
			if debugErr := a.debug("Automatic browser launch failed"); debugErr != nil {
				return Token{}, debugErr
			}
		} else {
			if debugErr := a.debug("Automatic browser launch started"); debugErr != nil {
				return Token{}, debugErr
			}
		}
	}

	a.status("Waiting for OCM authorization callback...")
	select {
	case completed := <-result:
		if completed.err != nil {
			return Token{}, completed.err
		}
		token, err := accessTokenOnly(completed.token)
		if err != nil {
			return Token{}, err
		}
		if err := a.debug("OCM authorization-code flow completed"); err != nil {
			token.AccessToken = ""
			return Token{}, err
		}
		return token, nil
	case <-callbackCtx.Done():
		if ctx.Err() != nil {
			if err := a.debug("OCM authorization callback wait canceled"); err != nil {
				return Token{}, err
			}
			return Token{}, ctx.Err()
		}
		if err := a.debug("OCM authorization callback wait timed out"); err != nil {
			return Token{}, err
		}
		return Token{}, errors.New("OCM authorization timed out waiting for callback")
	}
}

func authCodeHandler(ctx context.Context, config *oauth2.Config, expectedState, verifier string, result chan<- authCodeResult, debug func(string, ...any) error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			if !writeAuthCodeDebug(w, result, debug, "OCM callback rejected an unexpected HTTP method") {
				return
			}
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		query := request.URL.Query()
		if subtle.ConstantTimeCompare([]byte(query.Get("state")), []byte(expectedState)) != 1 {
			if !writeAuthCodeDebug(w, result, debug, "OCM callback rejected an invalid OAuth state") {
				return
			}
			http.Error(w, "invalid OAuth state", http.StatusBadRequest)
			return
		}
		if query.Get("error") != "" {
			if !writeAuthCodeDebug(w, result, debug, "OCM authorization callback reported an OAuth error") {
				return
			}
			http.Error(w, "authorization was not completed", http.StatusBadRequest)
			sendAuthCodeResult(result, authCodeResult{err: errors.New("OCM authorization failed")})
			return
		}
		code := query.Get("code")
		if code == "" {
			if !writeAuthCodeDebug(w, result, debug, "OCM callback did not contain an authorization code") {
				return
			}
			http.Error(w, "authorization response did not include a code", http.StatusBadRequest)
			sendAuthCodeResult(result, authCodeResult{err: errors.New("OCM authorization response did not include a code")})
			return
		}

		if !writeAuthCodeDebug(w, result, debug, "OCM callback received and state validated; exchanging authorization code") {
			return
		}
		token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
		if err != nil {
			if !writeAuthCodeDebug(w, result, debug, "OCM authorization-code exchange failed") {
				return
			}
			http.Error(w, "authorization exchange failed", http.StatusBadGateway)
			sendAuthCodeResult(result, authCodeResult{err: errors.New("exchange OCM authorization code failed")})
			return
		}
		if !writeAuthCodeDebug(w, result, debug, "OCM authorization-code exchange completed") {
			token.AccessToken = ""
			token.RefreshToken = ""
			return
		}
		_, _ = io.WriteString(w, "Login successful. You may close this window and return to the terminal.")
		sendAuthCodeResult(result, authCodeResult{token: token})
	})
}

func writeAuthCodeDebug(w http.ResponseWriter, result chan<- authCodeResult, debug func(string, ...any) error, message string) bool {
	if err := callDebug(debug, message); err != nil {
		http.Error(w, "local debug output failed", http.StatusInternalServerError)
		sendAuthCodeResult(result, authCodeResult{err: fmt.Errorf("write OCM debug output: %w", err)})
		return false
	}
	return true
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

func (a *Authenticator) debug(format string, args ...any) error {
	if err := callDebug(a.Debug, format, args...); err != nil {
		return fmt.Errorf("write OCM debug output: %w", err)
	}
	return nil
}

func callDebug(debug func(string, ...any) error, format string, args ...any) error {
	if debug != nil {
		return debug(format, args...)
	}
	return nil
}

func openBrowser(target string) error {
	return open.Run(target)
}
