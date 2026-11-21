package cmd

import (
	"context"
	"fmt"
	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/lambda"
)

type closeServiceFactory func() (closeService, error)

// sessionCloseTarget identifies what a close request would act on. The
// investigation is taken from the service's own task tags, not from whatever
// the user typed on the command line.
type sessionCloseTarget struct {
	ClusterID       string
	InvestigationID string
	SessionID       string
	AccessPointID   string
}

func (t sessionCloseTarget) valid() bool {
	return t.ClusterID != "" && t.InvestigationID != "" && t.SessionID != ""
}

// resolveSessionCloseTarget reads the investigation identity recorded on the
// task by the service that launched it.
func resolveSessionCloseTarget(ctx context.Context, ecsClient *awsclient.ECSClient, sessionID string) (sessionCloseTarget, error) {
	task, err := ecsClient.DescribeTask(ctx, sessionID)
	if err != nil {
		return sessionCloseTarget{}, fmt.Errorf("cannot identify the investigation for session %s: %w", sessionID, err)
	}
	target := sessionCloseTarget{
		ClusterID:       task.Tags["cluster_id"],
		InvestigationID: task.Tags["investigation_id"],
		SessionID:       sessionID,
		AccessPointID:   task.Tags["access_point_id"],
	}
	if !target.valid() {
		return sessionCloseTarget{}, fmt.Errorf("session %s has no investigation identity tags; close cannot be requested for it", sessionID)
	}
	return target, nil
}

// requireOpenForJoin is a best-effort admission check, not an ECS authorization fence.
func requireOpenForJoin(ctx context.Context, service closeService, target sessionCloseTarget) error {
	status, err := service.client.CloseStatus(ctx, service.idToken, lambda.CloseActionRequest{
		ClusterID: target.ClusterID, InvestigationID: target.InvestigationID,
	})
	if err != nil {
		return fmt.Errorf("cannot verify close status for %s/%s; session was not joined: %w", target.ClusterID, target.InvestigationID, err)
	}
	if status == nil || status.ClusterID != target.ClusterID || status.InvestigationID != target.InvestigationID {
		return fmt.Errorf("no matching close status for %s/%s; session was not joined", target.ClusterID, target.InvestigationID)
	}
	if status.Status != lambda.CloseStatusNone || status.OpenRequests != 0 || status.Seal != "none" || !status.AccessPointPresent {
		return fmt.Errorf("investigation %s/%s is not open for join (close status: %s, seal: %s)", target.ClusterID, target.InvestigationID, status.Status, status.Seal)
	}
	if target.AccessPointID == "" || target.AccessPointID != status.JoinAccessPointID {
		return fmt.Errorf("session %s does not identify a matching open workspace; session was not joined", target.SessionID)
	}
	return nil
}
