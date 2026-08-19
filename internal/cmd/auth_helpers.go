package cmd

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/spf13/cobra"

	"github.com/openshift-online/rosa-boundary/internal/auth"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	internalconfig "github.com/openshift-online/rosa-boundary/internal/config"
)

type AuthResult struct {
	AWSConfig   aws.Config
	Config      *internalconfig.Config
	IDToken     string
	Credentials *awsclient.TemporaryCredentials
}

func GetAWSConfigWithOIDC(cmd *cobra.Command, forceLogin bool) (*AuthResult, error) {
	ctx := cmd.Context()

	cfg, err := getConfig(true)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	pkce := auth.PKCEConfig{
		KeycloakURL: cfg.KeycloakURL,
		Realm:       cfg.KeycloakRealm,
		ClientID:    cfg.OIDCClientID,
	}
	idToken, err := auth.GetToken(ctx, pkce, forceLogin)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	sessionName := "rosa-boundary-session"
	creds, err := awsclient.AssumeRoleWithWebIdentity(
		ctx,
		cfg.AWSRegion,
		cfg.SRERoleARN,
		idToken,
		sessionName,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to assume AWS role via OIDC: %w", err)
	}

	credProvider := awsclient.StaticCredentialsProvider(creds)
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.AWSRegion),
		config.WithCredentialsProvider(credProvider),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build AWS config: %w", err)
	}

	return &AuthResult{
		AWSConfig:   awsCfg,
		Config:      cfg,
		IDToken:     idToken,
		Credentials: creds,
	}, nil
}

func AddForceLoginFlag(cmd *cobra.Command, target *bool) {
	cmd.Flags().BoolVar(target, "force-login", false, "Force re-authentication with Keycloak OIDC provider")
}