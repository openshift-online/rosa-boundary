package cmd

import (
	"time"

	awsclient "github.com/openshift-online/rosa-boundary/internal/aws"
	"github.com/openshift-online/rosa-boundary/internal/output"
)

// Client intervals use a local monotonic clock. ECS intervals use only ECS
// timestamps and are not additive with client intervals, which can overlap them.
type sessionStartupTimings struct {
	LambdaRoundTripMS   int64                  `json:"lambda_round_trip_ms"`
	InvokeToRunningMS   *int64                 `json:"invoke_to_running_ms,omitempty"`
	ECS                 *awsclient.TaskStartup `json:"ecs,omitempty"`
	ECSCreatedToPullMS  *int64                 `json:"ecs_created_to_pull_ms,omitempty"`
	ECSImagePullMS      *int64                 `json:"ecs_image_pull_ms,omitempty"`
	ECSAfterImagePullMS *int64                 `json:"ecs_after_image_pull_ms,omitempty"`
}

func (t *sessionStartupTimings) recordRunning(elapsedMS int64, startup *awsclient.TaskStartup) {
	t.InvokeToRunningMS = &elapsedMS
	if startup == nil {
		return
	}
	t.ECS = startup
	t.ECSCreatedToPullMS = elapsedMillis(startup.CreatedAt, startup.PullStartedAt)
	t.ECSImagePullMS = elapsedMillis(startup.PullStartedAt, startup.PullStoppedAt)
	t.ECSAfterImagePullMS = elapsedMillis(startup.PullStoppedAt, startup.StartedAt)
}

func elapsedMillis(start, end *time.Time) *int64 {
	if start == nil || end == nil || end.Before(*start) {
		return nil
	}
	ms := end.Sub(*start).Milliseconds()
	return &ms
}

func (t sessionStartupTimings) print() {
	// Diagnostics are best effort: a stderr failure must not fail session creation.
	_ = output.Debug("Startup timing: Lambda round trip %d ms", t.LambdaRoundTripMS)
	if t.InvokeToRunningMS == nil {
		return
	}
	_ = output.Debug("Startup timing: invocation to RUNNING observed %d ms", *t.InvokeToRunningMS)
	for _, phase := range []struct {
		label string
		ms    *int64
	}{
		{"ECS task creation to pull start", t.ECSCreatedToPullMS},
		{"ECS image pull", t.ECSImagePullMS},
		{"ECS pull complete to task start", t.ECSAfterImagePullMS},
	} {
		if phase.ms != nil {
			_ = output.Debug("Startup timing: %s %d ms", phase.label, *phase.ms)
		} else {
			_ = output.Debug("Startup timing: %s unavailable", phase.label)
		}
	}
}
