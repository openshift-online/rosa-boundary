package aws

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithy "github.com/aws/smithy-go"
)

// rolesTagKey is the AWS session-tag key carrying SRE role/group membership in
// the "https://aws.amazon.com/tags" OIDC claim. It is the AWS tag-key name, not
// the SRE group name, so it is safe to reference here.
const rolesTagKey = "roles"

// errMissingRequiredRole translates the STS rejection of an OIDC token that
// lacks the required role tag into an actionable authorization message. AWS
// STS/IAM remains the authorization authority; this is UX classification only.
var errMissingRequiredRole = errors.New(
	"access denied: your OIDC token is missing the required ROSA Boundary role claim; " +
		"verify your SRE role/group membership")

// TemporaryCredentials holds AWS STS short-term credentials.
type TemporaryCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
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
		// Translate only the known missing-role authorization failure; preserve
		// every other STS error as-is.
		if friendly := classifyKnownNegativeAuthError(err, idToken); friendly != nil {
			return nil, friendly
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

	// Capture expiration timestamp from STS response
	expiration := aws.ToTime(out.Credentials.Expiration)
	if expiration.IsZero() {
		return nil, fmt.Errorf("STS returned credentials with missing expiration")
	}

	return &TemporaryCredentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		Expiration:      expiration,
	}, nil
}

// classifyKnownNegativeAuthError returns errMissingRequiredRole only for the
// exact missing-role condition, and nil otherwise so the caller preserves the
// original STS error. Classification is intentionally narrow and requires BOTH:
//
//  1. AWS reports InvalidParameterValue with the specific transitive-tag-key
//     semantic; AND
//  2. the already-obtained OIDC token shows "roles" declared in
//     transitive_tag_keys but absent from principal_tags.
//
// The token inspection is diagnostic only — it does not make an authorization
// decision or replace STS token validation.
func classifyKnownNegativeAuthError(err error, idToken string) error {
	if err == nil {
		return nil
	}

	// Prefer typed error inspection; still check the message for the specific
	// semantic because InvalidParameterValue is a generic code.
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return nil
	}
	if apiErr.ErrorCode() != "InvalidParameterValue" {
		return nil
	}
	if !isTransitiveTagMissingMessage(apiErr.ErrorMessage()) {
		return nil
	}

	if !tokenMissingRolesPrincipalTag(idToken) {
		return nil
	}

	return errMissingRequiredRole
}

// isTransitiveTagMissingMessage reports whether an InvalidParameterValue message
// describes the specific "transitive tag key must be included in the requested
// tags" condition, rather than any other invalid-parameter situation.
func isTransitiveTagMissingMessage(msg string) bool {
	m := strings.ToLower(msg)
	return strings.Contains(m, "transitive tag key") && strings.Contains(m, "must be included")
}

// awsTagsClaim mirrors the relevant fields of the "https://aws.amazon.com/tags"
// OIDC claim used for AWS session tagging (ABAC).
type awsTagsClaim struct {
	TransitiveTagKeys []string            `json:"transitive_tag_keys"`
	PrincipalTags     map[string][]string `json:"principal_tags"`
}

// tokenMissingRolesPrincipalTag reports whether "roles" is present in
// transitive_tag_keys but absent from principal_tags. Any parse failure returns
// false so the caller preserves the original AWS error rather than guessing.
func tokenMissingRolesPrincipalTag(idToken string) bool {
	tags, err := parseAWSTagsClaim(idToken)
	if err != nil {
		return false
	}
	declaredTransitive := slices.Contains(tags.TransitiveTagKeys, rolesTagKey)
	_, hasPrincipalTag := tags.PrincipalTags[rolesTagKey]
	return declaredTransitive && !hasPrincipalTag
}

// parseAWSTagsClaim decodes the JWT payload and extracts the AWS session-tags
// claim. It performs no signature validation and is diagnostic only.
func parseAWSTagsClaim(idToken string) (awsTagsClaim, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return awsTagsClaim{}, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return awsTagsClaim{}, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims struct {
		AWSTags awsTagsClaim `json:"https://aws.amazon.com/tags"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return awsTagsClaim{}, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return claims.AWSTags, nil
}

// StaticCredentialsProvider returns an aws.CredentialsProvider backed by temporary credentials.
func StaticCredentialsProvider(creds *TemporaryCredentials) aws.CredentialsProvider {
	return credentials.NewStaticCredentialsProvider(
		creds.AccessKeyID,
		creds.SecretAccessKey,
		creds.SessionToken,
	)
}
