package authorization

import "github.com/sirupsen/logrus"

// AWSRequest is what an AWS action is asking to do. It is deliberately
// separate from Request: the Kubernetes rules (namespaces, secret allowlist)
// have no meaning for AWS, and sharing one type would let an AWS request be
// silently judged by them.
type AWSRequest struct {
	Region   string
	Resource string
	// Operation is the mutation the action performs, empty for a read. It is
	// the action's own declaration rather than anything the caller sends, so a
	// request cannot present itself as a read to get past the write allowlist.
	Operation string
}

// DefaultAllowedOperations is the write allowlist applied when none is
// configured, and it is empty — that is the whole point: a server nobody has
// configured for writes can read AWS but cannot change it. Mutating a
// cluster's cloud infrastructure is not something a deployment should acquire
// by default, so it is switched on by naming the operations, one at a time,
// in server configuration.
var DefaultAllowedOperations = []string{}

// AWSPolicy is the server-side policy an AWS authorizer enforces.
//
// Which regions are reachable is deliberately not here. An AWS action's
// region is always the target cluster's own, so bounding it is bounding which
// clusters the deployment may act on — a question that is not specific to AWS
// and is answered once, for every scope, by the executor's cluster-region
// allowlist (config.AllowedClusterRegions). This policy covers only what is
// peculiar to AWS: whether an action may change what it can see.
type AWSPolicy struct {
	// AllowedOperations names the mutations that are permitted. Empty denies
	// every write while still allowing reads.
	AllowedOperations []string
}

type AWSAuthorizer interface {
	Authorize(req AWSRequest) Result
}

type awsAuthorizer struct {
	logger            *logrus.Logger
	allowedOperations map[string]bool
}

var _ AWSAuthorizer = (*awsAuthorizer)(nil)

func NewAWS(logger *logrus.Logger, policy AWSPolicy) AWSAuthorizer {
	return &awsAuthorizer{
		logger:            logger,
		allowedOperations: stringSet(policy.AllowedOperations),
	}
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool, len(values))
	for _, value := range values {
		set[value] = true
	}
	return set
}

func (a *awsAuthorizer) Authorize(req AWSRequest) Result {
	if req.Resource == "" {
		return Result{Allowed: false, Reason: "resource is required"}
	}

	// The region is resolved from the cluster before this runs, so an empty
	// one here means that resolution produced nothing — a static provider with
	// no region configured. Refused rather than passed on: an action whose
	// region is unknown is one nothing has been able to judge, including the
	// cluster-region allowlist upstream.
	if req.Region == "" {
		return Result{Allowed: false, Reason: "region is required"}
	}

	// A write has to clear this gate, because being allowed to look at a
	// cluster's AWS account is not the same as being allowed to change what is
	// in it — and the default server allows the first and not the second.
	if req.Operation != "" && !a.allowedOperations[req.Operation] {
		a.logger.WithFields(logrus.Fields{
			"operation": req.Operation,
			"region":    req.Region,
		}).Warn("AWS write operation is not permitted by the server's allowlist")
		return Result{Allowed: false, Reason: "AWS write operation not permitted: " + req.Operation}
	}

	return Result{Allowed: true, Reason: "authorized"}
}
