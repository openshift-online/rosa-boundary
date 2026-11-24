package authorization

import (
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

// newTestAWSAuthorizer is the default posture: reads permitted, no writes.
func newTestAWSAuthorizer() AWSAuthorizer {
	return NewAWS(logrus.New(), AWSPolicy{})
}

// newTestAWSWriteAuthorizer is the same with writes configured. Separate so
// the read tests keep asserting against the default posture — no writes
// permitted — rather than quietly gaining them.
func newTestAWSWriteAuthorizer(operations []string) AWSAuthorizer {
	return NewAWS(logrus.New(), AWSPolicy{AllowedOperations: operations})
}

// Without a resource there is nothing to read, and nothing meaningful to
// record in the audit trail either.
func TestAWSAuthorize_ResourceRequired(t *testing.T) {
	authz := newTestAWSAuthorizer()

	result := authz.Authorize(AWSRequest{Region: "us-east-1"})

	if result.Allowed {
		t.Error("expected denied when no resource is named, got allowed")
	}
	if result.Reason == "" {
		t.Error("expected a denial reason, got empty string")
	}
}

// An empty region means the cluster's region could not be resolved. Nothing
// upstream — including the executor's cluster-region allowlist — was able to
// judge where this request would land, so it is refused rather than run.
func TestAWSAuthorize_EmptyRegionDenied(t *testing.T) {
	authz := newTestAWSAuthorizer()

	result := authz.Authorize(AWSRequest{Resource: "ec2-instances"})

	if result.Allowed {
		t.Error("expected denied when no region is named, got allowed")
	}
}

func TestAWSAuthorize_ReadAllowed(t *testing.T) {
	authz := newTestAWSAuthorizer()

	result := authz.Authorize(AWSRequest{Region: "eu-west-1", Resource: "ec2-instances"})

	if !result.Allowed {
		t.Errorf("expected allowed, got denied: %s", result.Reason)
	}
}

// The write gate's fail-closed case, and the one that matters most: an
// otherwise perfectly valid request is still refused because nobody
// configured this server to perform writes. Reads keep working — that is the
// whole distinction the gate exists to draw.
func TestAWSAuthorize_WriteDeniedByDefault(t *testing.T) {
	authz := newTestAWSAuthorizer()

	write := authz.Authorize(AWSRequest{Region: "us-east-1", Resource: "ec2-instances", Operation: "reboot"})
	if write.Allowed {
		t.Error("expected a write to be denied with no operation allowlist configured, got allowed")
	}
	if write.Reason == "" {
		t.Error("expected a denial reason, got empty string")
	}

	read := authz.Authorize(AWSRequest{Region: "us-east-1", Resource: "ec2-instances"})
	if !read.Allowed {
		t.Errorf("expected a read in the same region to stay allowed, got denied: %s", read.Reason)
	}
}

// And the default constant has to be the thing that produces that posture.
func TestDefaultAllowedOperationsIsEmpty(t *testing.T) {
	if len(DefaultAllowedOperations) != 0 {
		t.Errorf("expected no operations to be permitted by default, got %v", DefaultAllowedOperations)
	}
}

func TestAWSAuthorize_AllowedOperation(t *testing.T) {
	authz := newTestAWSWriteAuthorizer([]string{"reboot"})

	result := authz.Authorize(AWSRequest{Region: "us-east-1", Resource: "ec2-instances", Operation: "reboot"})

	if !result.Allowed {
		t.Errorf("expected allowed, got denied: %s", result.Reason)
	}
}

// Permitting one operation must not permit the others. Enabling reboots is a
// much smaller decision than enabling terminations, and an allowlist that
// could not tell them apart would collapse the two into one.
func TestAWSAuthorize_OtherOperationStillDenied(t *testing.T) {
	authz := newTestAWSWriteAuthorizer([]string{"reboot"})

	result := authz.Authorize(AWSRequest{Region: "us-east-1", Resource: "ec2-instances", Operation: "terminate"})

	if result.Allowed {
		t.Error("expected terminate to be denied when only reboot is permitted, got allowed")
	}
	if !strings.Contains(result.Reason, "terminate") {
		t.Errorf("expected the denial to name the refused operation, got %q", result.Reason)
	}
}
