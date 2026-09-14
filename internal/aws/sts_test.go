package aws

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	smithy "github.com/aws/smithy-go"
)

// makeJWT builds an unsigned JWT whose payload carries the given AWS session-tags
// claim. Only the payload is meaningful for the diagnostic classification logic.
func makeJWT(t *testing.T, tags map[string]any) string {
	t.Helper()
	payload := map[string]any{"sub": "test-user"}
	if tags != nil {
		payload["https://aws.amazon.com/tags"] = tags
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	return header + "." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

// transitiveTagError is the low-level error AWS STS returns for the #274 condition.
func transitiveTagError() error {
	return fmt.Errorf("AssumeRoleWithWebIdentity failed: %w", &smithy.GenericAPIError{
		Code:    "InvalidParameterValue",
		Message: "The specified transitive tag key must be included in the requested tags.",
	})
}

func TestClassifyKnownNegativeAuthError_MissingRolesPrincipalTag(t *testing.T) {
	// Case 1: InvalidParameterValue + transitive_tag_keys has "roles" +
	// principal_tags.roles absent => friendly missing-required-role error.
	token := makeJWT(t, map[string]any{
		"transitive_tag_keys": []string{"uuid", "roles"},
		"principal_tags": map[string][]string{
			"uuid": {"abc-123"},
		},
	})

	got := classifyKnownNegativeAuthError(transitiveTagError(), token)
	if !errors.Is(got, errMissingRequiredRole) {
		t.Fatalf("expected errMissingRequiredRole, got %v", got)
	}
}

func TestClassifyKnownNegativeAuthError_RolesPrincipalTagPresent(t *testing.T) {
	// Case 2: same AWS error but principal_tags.roles exists => do NOT classify.
	token := makeJWT(t, map[string]any{
		"transitive_tag_keys": []string{"uuid", "roles"},
		"principal_tags": map[string][]string{
			"uuid":  {"abc-123"},
			"roles": {"ai-sd-sre"},
		},
	})

	if got := classifyKnownNegativeAuthError(transitiveTagError(), token); got != nil {
		t.Fatalf("expected nil (not classified), got %v", got)
	}
}

func TestClassifyKnownNegativeAuthError_OtherInvalidParameterValue(t *testing.T) {
	// Case 3: InvalidParameterValue for another reason => preserve original error.
	token := makeJWT(t, map[string]any{
		"transitive_tag_keys": []string{"uuid", "roles"},
		"principal_tags": map[string][]string{
			"uuid": {"abc-123"},
		},
	})
	otherErr := fmt.Errorf("AssumeRoleWithWebIdentity failed: %w", &smithy.GenericAPIError{
		Code:    "InvalidParameterValue",
		Message: "1 validation error detected: value at 'roleArn' failed to satisfy constraint.",
	})

	if got := classifyKnownNegativeAuthError(otherErr, token); got != nil {
		t.Fatalf("expected nil (not classified), got %v", got)
	}
}

func TestClassifyKnownNegativeAuthError_AccessDenied(t *testing.T) {
	// Case 4: a different STS error code => preserve original error.
	token := makeJWT(t, map[string]any{
		"transitive_tag_keys": []string{"uuid", "roles"},
		"principal_tags": map[string][]string{
			"uuid": {"abc-123"},
		},
	})
	accessDenied := fmt.Errorf("AssumeRoleWithWebIdentity failed: %w", &smithy.GenericAPIError{
		Code:    "AccessDenied",
		Message: "Not authorized to perform sts:AssumeRoleWithWebIdentity",
	})

	if got := classifyKnownNegativeAuthError(accessDenied, token); got != nil {
		t.Fatalf("expected nil (not classified), got %v", got)
	}
}

func TestClassifyKnownNegativeAuthError_MalformedToken(t *testing.T) {
	// Case 5: malformed / unparseable JWT => preserve original error.
	for _, token := range []string{
		"",
		"not-a-jwt",
		"only.two",
		"a.!!!invalid-base64!!!.c",
	} {
		if got := classifyKnownNegativeAuthError(transitiveTagError(), token); got != nil {
			t.Fatalf("token %q: expected nil (not classified), got %v", token, got)
		}
	}
}

func TestClassifyKnownNegativeAuthError_NonAPIError(t *testing.T) {
	// A plain (non-Smithy) error must never be classified.
	token := makeJWT(t, map[string]any{
		"transitive_tag_keys": []string{"uuid", "roles"},
		"principal_tags":      map[string][]string{"uuid": {"abc-123"}},
	})
	if got := classifyKnownNegativeAuthError(errors.New("network timeout"), token); got != nil {
		t.Fatalf("expected nil (not classified), got %v", got)
	}
	if got := classifyKnownNegativeAuthError(nil, token); got != nil {
		t.Fatalf("expected nil for nil error, got %v", got)
	}
}

func TestClassifyKnownNegativeAuthError_NoAWSTagsClaim(t *testing.T) {
	// Token parses but carries no AWS tags claim => preserve original error.
	token := makeJWT(t, nil)
	if got := classifyKnownNegativeAuthError(transitiveTagError(), token); got != nil {
		t.Fatalf("expected nil (not classified), got %v", got)
	}
}
