package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/openshift-online/rosa-boundary/internal/output"
)

const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

// deviceError contains only local, bounded descriptions. Provider response
// bodies and secrets must never be included in errors or debug output.
type deviceError struct {
	reason string
	text   string
}

func (e *deviceError) Error() string  { return e.text }
func (e *deviceError) Reason() string { return e.reason }

type deviceAuthorization struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int64  `json:"expires_in"`
	Interval        int64  `json:"interval"`
}

type deviceTokenReply struct {
	IDToken string `json:"id_token"`
	Error   string `json:"error"`
}

func acquireDeviceToken(ctx context.Context, cfg PKCEConfig, opts Options) (string, error) {
	if cfg.KeycloakURL == "" || cfg.Realm == "" || cfg.ClientID == "" {
		return "", &deviceError{"invalid_response", "device authorization requires an OIDC URL, realm and client ID"}
	}
	client := opts.httpClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	base := issuerForConfig(cfg) + "/protocol/openid-connect/"
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return "", &deviceError{"other", "cannot generate device authorization PKCE challenge"}
	}
	form := url.Values{
		"client_id": {cfg.ClientID}, "scope": {"openid profile email"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
	}
	var authorization deviceAuthorization
	status, err := postDeviceForm(ctx, client, base+"auth/device", form, &authorization)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", &deviceError{"other", fmt.Sprintf("device authorization endpoint returned HTTP %d", status)}
	}
	verification, parseErr := url.Parse(authorization.VerificationURI)
	if authorization.DeviceCode == "" || authorization.UserCode == "" || authorization.ExpiresIn <= 0 || authorization.ExpiresIn > 3600 ||
		parseErr != nil || (verification.Scheme != "https" && verification.Scheme != "http") || verification.Host == "" ||
		strings.Contains(authorization.VerificationURI, authorization.DeviceCode) || len(authorization.UserCode) > 128 || len(authorization.VerificationURI) > 2048 {
		return "", &deviceError{"invalid_response", "device authorization endpoint returned an invalid challenge"}
	}
	for _, r := range authorization.UserCode + authorization.VerificationURI {
		if r < 0x20 || r == 0x7f {
			return "", &deviceError{"invalid_response", "device authorization endpoint returned an invalid challenge"}
		}
	}
	if err := opts.Reporter.Emit("boundary", "device_authorization", map[string]any{
		"verification_uri": authorization.VerificationURI, "user_code": authorization.UserCode, "expires_in": authorization.ExpiresIn,
	}); err != nil {
		return "", fmt.Errorf("authentication status write failed: %w", err)
	}
	if opts.Reporter == nil || opts.Reporter.Format != "json" {
		output.Status("Open %s on another device and enter code %s. Waiting for approval...", authorization.VerificationURI, authorization.UserCode)
	}
	interval := time.Duration(authorization.Interval) * time.Second
	if interval < time.Second {
		interval = 5 * time.Second
	}
	// Refuse an unreasonable interval rather than overflow a timer or exceed expiry.
	if interval > time.Duration(authorization.ExpiresIn)*time.Second {
		return "", &deviceError{"invalid_response", "device authorization endpoint returned an invalid polling interval"}
	}
	pollCtx, cancel := context.WithTimeout(ctx, time.Duration(authorization.ExpiresIn)*time.Second)
	defer cancel()
	wait := opts.wait
	if wait == nil {
		wait = waitForDevicePoll
	}
	for {
		if err := wait(pollCtx, interval); err != nil {
			return "", deviceContextError(ctx, err)
		}
		var reply deviceTokenReply
		status, err := postDeviceForm(pollCtx, client, base+"token", url.Values{
			"grant_type": {deviceGrant}, "device_code": {authorization.DeviceCode},
			"client_id": {cfg.ClientID}, "code_verifier": {verifier},
		}, &reply)
		if err != nil {
			return "", deviceContextError(ctx, err)
		}
		if status == http.StatusOK {
			if reply.IDToken == "" || reply.Error != "" {
				return "", &deviceError{"invalid_response", "device token endpoint returned an invalid ID token response"}
			}
			return reply.IDToken, nil
		}
		switch reply.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return "", &deviceError{"denied", "device authorization denied; run login again to retry"}
		case "expired_token":
			return "", &deviceError{"expired", "device authorization expired; run login again to retry"}
		default:
			return "", &deviceError{"invalid_response", fmt.Sprintf("device token endpoint returned invalid status (HTTP %d)", status)}
		}
	}
}

func deviceContextError(parent context.Context, err error) error {
	if errors.Is(parent.Err(), context.Canceled) {
		return &deviceError{"canceled", "device authorization canceled"}
	}
	if errors.Is(parent.Err(), context.DeadlineExceeded) {
		return &deviceError{"expired", "device authorization expired; run login again to retry"}
	}
	if errors.Is(err, context.Canceled) {
		return &deviceError{"canceled", "device authorization canceled"}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &deviceError{"expired", "device authorization expired; run login again to retry"}
	}
	return err
}

func waitForDevicePoll(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func postDeviceForm(ctx context.Context, client *http.Client, endpoint string, values url.Values, result any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return 0, &deviceError{"invalid_response", "cannot construct device authorization request"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return 0, deviceContextError(ctx, &deviceError{"network", "device authorization network request failed"})
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(result); err != nil {
		return 0, &deviceError{"invalid_response", "device authorization endpoint returned invalid JSON"}
	}
	return resp.StatusCode, nil
}
