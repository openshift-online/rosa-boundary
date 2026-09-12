package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// TemporaryCredentials holds AWS STS short-term credentials.
type TemporaryCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

// AssumeRoleWithWebIdentity calls STS to exchange an OIDC token for temporary AWS credentials.
// This is a public STS operation — no ambient credentials are required.
//
// Session tags for ABAC are automatically extracted from the principal_tags.<ABAC_TAG_KEY> claim
// in the JWT token (or from the flattened https://aws.amazon.com/tags/principal_tags/<ABAC_TAG_KEY>
// claim as a fallback). These session tags become available as aws:PrincipalTag/<ABAC_TAG_KEY> in
// IAM policy conditions. The OIDC role trust policy must include sts:TagSession permission for
// session tags to be applied. See the architecture overview documentation for Keycloak mapper
// configuration details.
// newSTSClient is a variable to allow mocking in tests.
var newSTSClient = func(region string) *sts.Client {
	return sts.New(sts.Options{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
	})
}

func AssumeRoleWithWebIdentity(ctx context.Context, region, roleARN, idToken, sessionName string) (*TemporaryCredentials, error) {
	// Use anonymous credentials since AssumeRoleWithWebIdentity doesn't require them.
	client := newSTSClient(region)

	out, err := client.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(idToken),
	})
	if err != nil {
		var httpErr interface{ HTTPStatusCode() int }
		if (errors.As(err, &httpErr) && httpErr.HTTPStatusCode() == 400) || strings.Contains(err.Error(), "StatusCode: 400") {
			return nil, fmt.Errorf("You are not a member of the required realm roles: %w", err)
		}
		return nil, fmt.Errorf("AssumeRoleWithWebIdentity failed: %w", err)
	}

	if out.Credentials == nil {
		return nil, fmt.Errorf("STS returned nil credentials")
	}

	// Validate that credential strings are non-empty after aws.ToString conversion
	accessKeyID := aws.ToString(out.Credentials.AccessKeyId)
	secretAccessKey := aws.ToString(out.Credentials.SecretAccessKey)
	sessionToken := aws.ToString(out.Credentials.SessionToken)

	if accessKeyID == "" || secretAccessKey == "" || sessionToken == "" {
		return nil, fmt.Errorf("STS returned credentials with empty values")
	}

	return &TemporaryCredentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
	}, nil
}

// StaticCredentialsProvider returns an aws.CredentialsProvider backed by temporary credentials.
func StaticCredentialsProvider(creds *TemporaryCredentials) aws.CredentialsProvider {
	return credentials.NewStaticCredentialsProvider(
		creds.AccessKeyID,
		creds.SecretAccessKey,
		creds.SessionToken,
	)
}
