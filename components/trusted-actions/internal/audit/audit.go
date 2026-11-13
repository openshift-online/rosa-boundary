package audit

import (
	"time"

	"github.com/openshift-online/rosa-trusted-actions/internal/actions"
)

type Decision string

const (
	DecisionAllowed Decision = "allowed"
	DecisionDenied  Decision = "denied"
)

type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeSkipped Outcome = "skipped"
)

type Record struct {
	Timestamp time.Time `json:"timestamp"`
	CallerID  string    `json:"caller_id"`
	Action    string    `json:"action"`
	// Target holds the scope-specific target the action ran against; its
	// concrete type determines the shape of the serialized payload.
	Target    actions.Target `json:"target"`
	ClusterID string         `json:"cluster_id"`
	// ClusterRegion is the target cluster's own AWS region, as resolved from
	// OCM for the deployment-boundary check. Empty when resolution never ran
	// (e.g. no execution scope matched the action).
	ClusterRegion string   `json:"cluster_region,omitempty"`
	Decision      Decision `json:"decision"`
	DenyReason    string   `json:"deny_reason,omitempty"`
	Outcome       Outcome  `json:"outcome"`
	Error         string   `json:"error,omitempty"`
}

type Logger interface {
	Log(record Record)
}
