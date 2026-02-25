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
		RawSession: rawSession,
	}, nil
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
