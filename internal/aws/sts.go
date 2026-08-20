package aws

import (
	"context"
	"fmt"

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
func AssumeRoleWithWebIdentity(ctx context.Context, region, roleARN, idToken, sessionName string) (*TemporaryCredentials, error) {
	// Use anonymous credentials since AssumeRoleWithWebIdentity doesn't require them.
	client := sts.New(sts.Options{
		Region:      region,
		Credentials: aws.AnonymousCredentials{},
	})

	out, err := client.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(roleARN),
		RoleSessionName:  aws.String(sessionName),
		WebIdentityToken: aws.String(idToken),
	})
	if err != nil {
		return nil, fmt.Errorf("AssumeRoleWithWebIdentity failed: %w", err)
	}

	if out.Credentials == nil {
		return nil, fmt.Errorf("STS returned nil credentials")
	}

	return &TemporaryCredentials{
		AccessKeyID:     aws.ToString(out.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(out.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(out.Credentials.SessionToken),
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
