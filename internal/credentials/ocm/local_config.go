package ocm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// SaveLocalConfig signs into OCM and writes a one-shot workstation config.
// It does not read existing credentials or send them to a remote session.
func (a *Authenticator) SaveLocalConfig(ctx context.Context, path string, environment Environment, flow Flow) error {
	return a.saveLocalConfig(ctx, path, environment, flow, nil)
}

// MaintainLocalConfig signs in once and renews the workstation config until
// canceled. Cancellation after a successful write leaves the last file intact.
func (a *Authenticator) MaintainLocalConfig(ctx context.Context, path string, environment Environment, flow Flow) error {
	return a.saveLocalConfig(ctx, path, environment, flow, waitForLocalRefresh)
}

func (a *Authenticator) saveLocalConfig(ctx context.Context, path string, environment Environment, flow Flow, wait func(context.Context, time.Duration) error) error {
	if path == "" {
		return errors.New("an explicit local OCM config path is required")
	}
	if environment.URL == "" {
		return errors.New("an OCM environment is required")
	}
	approved, err := ResolveEnvironment(environment.URL)
	if err != nil {
		return err
	}
	if err := checkLocalConfigPath(path); err != nil {
		return err
	}
	grant := &onlineGrant{}
	token, err := a.acquire(ctx, flow, grant)
	if err != nil {
		return err
	}
	if grant.refresh == "" {
		return errors.New("OCM did not issue an online refresh grant")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := writeLocalConfig(path, approved.URL, token.AccessToken, grant.refresh); err != nil {
		return fmt.Errorf("write local OCM config: %w", err)
	}
	if wait == nil {
		return nil
	}
	a.status("Wrote %s OCM config to %s; keeping it refreshed until stopped", approved.Name, path)
	for {
		remaining := time.Until(token.Expiry)
		if remaining <= 2*RefreshTimeout {
			return errors.New("OCM access token has no usable lifetime for local renewal")
		}
		lead := max(RefreshTimeout, min(time.Minute, remaining/4))
		if err := wait(ctx, remaining-lead); err != nil {
			return localRefreshStopped(err)
		}
		token, err = a.refreshOnline(ctx, grant)
		if ctx.Err() != nil {
			return localRefreshStopped(ctx.Err())
		}
		if err != nil {
			return fmt.Errorf("%w; rerun the command to sign in again", err)
		}
		if time.Until(token.Expiry) <= 2*RefreshTimeout {
			return errors.New("refreshed OCM access token has no usable lifetime")
		}
		if err := writeLocalConfig(path, approved.URL, token.AccessToken, grant.refresh); err != nil {
			return fmt.Errorf("update local OCM config: %w", err)
		}
	}
}

func localRefreshStopped(err error) error {
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func waitForLocalRefresh(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

func checkLocalConfigPath(path string) error {
	info, err := os.Lstat(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("local OCM config path %q must be a regular file", path)
	}
	return nil
}

func writeLocalConfig(path, apiURL, access, refresh string) error {
	if err := checkLocalConfigPath(path); err != nil {
		return err
	}
	// CreateTemp uses 0600. Rename makes the token pair visible together and
	// replaces the inode rather than writing through links or old permissions.
	file, err := os.CreateTemp(filepath.Dir(path), ".ocm-config-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	cfg := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		URL          string `json:"url"`
		ClientID     string `json:"client_id"`
		TokenURL     string `json:"token_url"`
	}{access, refresh, apiURL, ClientID, TokenURL}
	writeErr := json.NewEncoder(file).Encode(cfg)
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
