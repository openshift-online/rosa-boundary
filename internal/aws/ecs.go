package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// ECSClient wraps the AWS ECS SDK client.
type ECSClient struct {
	client  *ecs.Client
	cluster string
}

// NewECSClient creates a new ECS client using the provided credentials provider.
func NewECSClient(region string, cluster string, credProvider aws.CredentialsProvider) *ECSClient {
	client := ecs.New(ecs.Options{
		Region:      region,
		Credentials: credProvider,
	})
	return &ECSClient{client: client, cluster: cluster}
}

// TaskSummary holds minimal info about an ECS task.
type TaskSummary struct {
	TaskID      string            `json:"task_id"`
	TaskARN     string            `json:"task_arn"`
	Status      string            `json:"status"`
	StartedAt   *time.Time        `json:"started_at,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	ClusterName string            `json:"cluster_name"`
}

// ExecuteCommandSession holds the response from ECS ExecuteCommand.
type ExecuteCommandSession struct {
	SessionID  string
	StreamURL  string
	TokenValue string
	// Target is the ECS Exec target string required by session-manager-plugin:
	// "ecs:<cluster>_<taskId>_<containerRuntimeId>"
	Target string
	// Raw JSON for passing to session-manager-plugin
	RawSession json.RawMessage
}

// DescribeTask fetches details for a single task.
func (c *ECSClient) DescribeTask(ctx context.Context, taskID string) (*TaskSummary, error) {
	out, err := c.client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
		Cluster: aws.String(c.cluster),
		Tasks:   []string{taskID},
		Include: []types.TaskField{types.TaskFieldTags},
	})
	if err != nil {
		return nil, fmt.Errorf("DescribeTasks failed: %w", err)
	}
	if len(out.Tasks) == 0 {
		return nil, fmt.Errorf("task %s not found in cluster %s", taskID, c.cluster)
	}

	return taskToSummary(out.Tasks[0], c.cluster), nil
}

// WaitForRunning polls until the task reaches RUNNING state or the context is cancelled.
func (c *ECSClient) WaitForRunning(ctx context.Context, taskID string) error {
	waiter := ecs.NewTasksRunningWaiter(c.client)
	return waiter.Wait(ctx, &ecs.DescribeTasksInput{
		Cluster: aws.String(c.cluster),
		Tasks:   []string{taskID},
	}, 10*time.Minute)
}

// WaitForStopped polls until the task reaches STOPPED state or the context is cancelled.
func (c *ECSClient) WaitForStopped(ctx context.Context, taskID string) error {
	waiter := ecs.NewTasksStoppedWaiter(c.client)
	return waiter.Wait(ctx, &ecs.DescribeTasksInput{
		Cluster: aws.String(c.cluster),
		Tasks:   []string{taskID},
	}, 10*time.Minute)
}

// ListRunningTasks returns all tasks with the given desired status.
func (c *ECSClient) ListRunningTasks(ctx context.Context, desiredStatus string) ([]TaskSummary, error) {
	var taskARNs []string
	paginator := ecs.NewListTasksPaginator(c.client, &ecs.ListTasksInput{
		Cluster:       aws.String(c.cluster),
		DesiredStatus: types.DesiredStatus(desiredStatus),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListTasks failed: %w", err)
		}
		taskARNs = append(taskARNs, page.TaskArns...)
	}

	if len(taskARNs) == 0 {
		return nil, nil
	}

	// DescribeTasks supports up to 100 tasks per call
	var summaries []TaskSummary
	for i := 0; i < len(taskARNs); i += 100 {
		end := i + 100
		if end > len(taskARNs) {
			end = len(taskARNs)
		}
		batch := taskARNs[i:end]

		out, err := c.client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
			Cluster: aws.String(c.cluster),
			Tasks:   batch,
			Include: []types.TaskField{types.TaskFieldTags},
		})
		if err != nil {
			return nil, fmt.Errorf("DescribeTasks failed: %w", err)
		}
		for _, t := range out.Tasks {
			summaries = append(summaries, *taskToSummary(t, c.cluster))
		}
	}

	return summaries, nil
}

// StopTask stops the given task with a reason string.
func (c *ECSClient) StopTask(ctx context.Context, taskID, reason string) error {
	_, err := c.client.StopTask(ctx, &ecs.StopTaskInput{
		Cluster: aws.String(c.cluster),
		Task:    aws.String(taskID),
		Reason:  aws.String(reason),
	})
	if err != nil {
		return fmt.Errorf("StopTask failed: %w", err)
	}
	return nil
}

// WaitForExecAgent polls DescribeTasks every 500 ms until the container's
// ExecuteCommandAgent reaches RUNNING state, the context is cancelled, or
// maxWait elapses. Call this before ExecuteCommand — the SSM data channel is
// closed immediately if the agent hasn't registered on its side yet.
func (c *ECSClient) WaitForExecAgent(ctx context.Context, taskID, container string, maxWait time.Duration) error {
	const pollInterval = 500 * time.Millisecond
	deadline := time.Now().Add(maxWait)
	for {
		ready, err := c.isExecAgentRunning(ctx, taskID, container)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("exec agent not ready after %s", maxWait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

func (c *ECSClient) isExecAgentRunning(ctx context.Context, taskID, container string) (bool, error) {
	out, err := c.client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
		Cluster: aws.String(c.cluster),
		Tasks:   []string{taskID},
	})
	if err != nil {
		return false, fmt.Errorf("DescribeTasks failed: %w", err)
	}
	if len(out.Tasks) == 0 {
		return false, fmt.Errorf("task %s not found", taskID)
	}
	for _, cont := range out.Tasks[0].Containers {
		if aws.ToString(cont.Name) != container {
			continue
		}
		for _, agent := range cont.ManagedAgents {
			if agent.Name == types.ManagedAgentNameExecuteCommandAgent {
				return aws.ToString(agent.LastStatus) == "RUNNING", nil
			}
		}
	}
	// Agent entry not present yet — still initialising.
	return false, nil
}

// ExecuteCommand calls ECS ExecuteCommand and returns the session details.
func (c *ECSClient) ExecuteCommand(ctx context.Context, taskID, container, command string) (*ExecuteCommandSession, error) {
	out, err := c.client.ExecuteCommand(ctx, &ecs.ExecuteCommandInput{
		Cluster:     aws.String(c.cluster),
		Task:        aws.String(taskID),
		Container:   aws.String(container),
		Command:     aws.String(command),
		Interactive: true,
	})
	if err != nil {
		return nil, fmt.Errorf("ExecuteCommand failed: %w", err)
	}

	if out.Session == nil {
		return nil, fmt.Errorf("ExecuteCommand returned nil session")
	}

	// Get the container RuntimeId so we can build the Target for session-manager-plugin.
	// The plugin requires: "ecs:<cluster>_<taskId>_<containerRuntimeId>"
	var target string
	descOut, descErr := c.client.DescribeTasks(ctx, &ecs.DescribeTasksInput{
		Cluster: aws.String(c.cluster),
		Tasks:   []string{taskID},
	})
	if descErr == nil && len(descOut.Tasks) > 0 {
		for _, cont := range descOut.Tasks[0].Containers {
			if aws.ToString(cont.Name) == container && cont.RuntimeId != nil {
				target = fmt.Sprintf("ecs:%s_%s_%s", c.cluster, taskID, aws.ToString(cont.RuntimeId))
				break
			}
		}
	}

	// Build the session JSON exactly as the session-manager-plugin expects it.
	sessionPayload := map[string]string{
		"sessionId":  aws.ToString(out.Session.SessionId),
		"streamUrl":  aws.ToString(out.Session.StreamUrl),
		"tokenValue": aws.ToString(out.Session.TokenValue),
	}
	rawSession, err := json.Marshal(sessionPayload)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal session: %w", err)
	}

	return &ExecuteCommandSession{
		SessionID:  aws.ToString(out.Session.SessionId),
		StreamURL:  aws.ToString(out.Session.StreamUrl),
		TokenValue: aws.ToString(out.Session.TokenValue),
		Target:     target,
		RawSession: rawSession,
	}, nil
}

// ListTaskDefinitionsByFamily returns all active task definition ARNs for a family prefix.
func (c *ECSClient) ListTaskDefinitionsByFamily(ctx context.Context, familyPrefix string) ([]string, error) {
	var arns []string
	paginator := ecs.NewListTaskDefinitionsPaginator(c.client, &ecs.ListTaskDefinitionsInput{
		FamilyPrefix: aws.String(familyPrefix),
		Status:       types.TaskDefinitionStatusActive,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("ListTaskDefinitions failed: %w", err)
		}
		arns = append(arns, page.TaskDefinitionArns...)
	}
	return arns, nil
}

// DeregisterTaskDefinition deregisters a task definition by ARN.
func (c *ECSClient) DeregisterTaskDefinition(ctx context.Context, taskDefinitionARN string) error {
	_, err := c.client.DeregisterTaskDefinition(ctx, &ecs.DeregisterTaskDefinitionInput{
		TaskDefinition: aws.String(taskDefinitionARN),
	})
	if err != nil {
		return fmt.Errorf("DeregisterTaskDefinition failed: %w", err)
	}
	return nil
}

// ListTasksByInvestigation returns running tasks tagged with the given investigation ID.
func (c *ECSClient) ListTasksByInvestigation(ctx context.Context, investigationID string) ([]TaskSummary, error) {
	tasks, err := c.ListRunningTasks(ctx, "RUNNING")
	if err != nil {
		return nil, err
	}
	var filtered []TaskSummary
	for _, t := range tasks {
		if t.Tags["investigation_id"] == investigationID {
			filtered = append(filtered, t)
		}
	}
	return filtered, nil
}

// taskToSummary converts an ECS task to a TaskSummary.
func taskToSummary(t types.Task, clusterName string) *TaskSummary {
	taskID := path.Base(aws.ToString(t.TaskArn))

	tags := make(map[string]string)
	for _, tag := range t.Tags {
		tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
	}

	// Resolve the cluster short name from the ARN if we only have an ARN.
	cluster := clusterName
	if strings.HasPrefix(aws.ToString(t.ClusterArn), "arn:") {
		cluster = path.Base(aws.ToString(t.ClusterArn))
	}

	return &TaskSummary{
		TaskID:      taskID,
		TaskARN:     aws.ToString(t.TaskArn),
		Status:      aws.ToString(t.LastStatus),
		StartedAt:   t.StartedAt,
		Tags:        tags,
		ClusterName: cluster,
	}
}
