package rta

import (
	"context"
	"fmt"

	ocmconfig "github.com/openshift-online/ocm-cli/pkg/config"
	sdk "github.com/openshift-online/ocm-sdk-go"
	"github.com/spf13/cobra"
)

// resolveToken returns a bearer token using the precedence:
// --token flag > OCM config file access token.
func (g *commandGroup) resolveToken(cmd *cobra.Command) ([]ClientOption, error) {
	if t := fromFlag(cmd, "token"); t != "" {
		return []ClientOption{WithToken(t)}, nil
	}

	cfg, err := ocmconfig.Load()
	if err != nil {
		return nil, fmt.Errorf("load OCM configuration: %w", err)
	}
	if cfg == nil {
		return nil, fmt.Errorf("not authenticated: use --token or log in with ocm")
	}

	bpConnBuilder := sdk.NewConnectionBuilder().
		URL(cfg.URL).TokenURL(cfg.TokenURL).
		Client(cfg.ClientID, cfg.ClientSecret)
	if cfg.AccessToken != "" {
		bpConnBuilder = bpConnBuilder.Tokens(cfg.AccessToken)
	}
	if cfg.RefreshToken != "" {
		bpConnBuilder = bpConnBuilder.Tokens(cfg.RefreshToken)
	}
	bpConn, err := bpConnBuilder.Build()
	if err != nil {
		return nil, fmt.Errorf("build OCM connection: %w", err)
	}

	return []ClientOption{
		WithTokenProvider(func(ctx context.Context) (string, error) {
			accessToken, _, err := bpConn.TokensContext(ctx)
			return accessToken, err
		}),
		WithCleaner(func() {
			if err := bpConn.Close(); err != nil {
				fmt.Printf("error closing OCM connection: %v\n", err)
			}
		}),
	}, nil
}
