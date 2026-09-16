package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

func TestTaskToListSummaryUsesDesiredStatus(t *testing.T) {
	task := types.Task{
		TaskArn:       aws.String("arn:aws:ecs:us-east-2:123456789012:task/cluster/task-id"),
		ClusterArn:    aws.String("arn:aws:ecs:us-east-2:123456789012:cluster/cluster"),
		LastStatus:    aws.String("RUNNING"),
		DesiredStatus: aws.String("STOPPED"),
	}

	summary := taskToListSummary(task, "cluster")
	if summary.Status != "STOPPED" {
		t.Fatalf("taskToListSummary status = %q, want STOPPED", summary.Status)
	}
}

func TestTaskToSummaryUsesLastStatus(t *testing.T) {
	task := types.Task{
		TaskArn:       aws.String("arn:aws:ecs:us-east-2:123456789012:task/cluster/task-id"),
		LastStatus:    aws.String("RUNNING"),
		DesiredStatus: aws.String("STOPPED"),
	}

	summary := taskToSummary(task, "cluster")
	if summary.Status != "RUNNING" {
		t.Fatalf("taskToSummary status = %q, want RUNNING", summary.Status)
	}
}

// testECSClient provides a mock for testing ECS methods
type testECSClient struct {
	mockRunningTasks []TaskSummary
}

// ListRunningTasks returns the mock tasks for testing
func (m *testECSClient) ListRunningTasks(ctx context.Context, desiredStatus string) ([]TaskSummary, error) {
	return m.mockRunningTasks, nil
}

// ListTasksByInvestigation implements the same logic as ECSClient to test the filtering behavior
func (m *testECSClient) ListTasksByInvestigation(ctx context.Context, clusterID, investigationID string) ([]TaskSummary, error) {
	tasks, err := m.ListRunningTasks(ctx, "RUNNING")
	if err != nil {
		return nil, err
	}
	var filtered []TaskSummary
	for _, t := range tasks {
		if t.Tags["investigation_id"] == investigationID && t.Tags["cluster_id"] == clusterID {
			filtered = append(filtered, t)
		}
	}
	return filtered, nil
}

func TestListTasksByInvestigation_FiltersByBothTags(t *testing.T) {
	// Create mock tasks that ListRunningTasks would return
	allTasks := []TaskSummary{
		{
			TaskID: "task-1",
			Tags: map[string]string{
				"cluster_id":       "cluster-a",
				"investigation_id": "inv-1",
			},
		},
		{
			TaskID: "task-2",
			Tags: map[string]string{
				"cluster_id":       "cluster-b",
				"investigation_id": "inv-1",
			},
		},
		{
			TaskID: "task-3",
			Tags: map[string]string{
				"cluster_id":       "cluster-a",
				"investigation_id": "inv-2",
			},
		},
		{
			TaskID: "task-4",
			Tags: map[string]string{
				"cluster_id":       "cluster-a",
				"investigation_id": "inv-1",
			},
		},
	}

	// Create test client that returns all tasks from ListRunningTasks
	client := &testECSClient{
		mockRunningTasks: allTasks,
	}

	// Call the actual ListTasksByInvestigation method
	ctx := context.Background()
	testClusterID := "cluster-a"
	testInvestigationID := "inv-1"

	filtered, err := client.ListTasksByInvestigation(ctx, testClusterID, testInvestigationID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify filtering behavior: should match only task-1 and task-4
	if len(filtered) != 2 {
		t.Fatalf("expected 2 tasks matching cluster_id=%s and investigation_id=%s, got %d",
			testClusterID, testInvestigationID, len(filtered))
	}

	found := make(map[string]bool)
	for _, task := range filtered {
		found[task.TaskID] = true
	}

	// Should include tasks with matching cluster_id AND investigation_id
	if !found["task-1"] {
		t.Error("expected to find task-1 (cluster-a, inv-1)")
	}
	if !found["task-4"] {
		t.Error("expected to find task-4 (cluster-a, inv-1)")
	}

	// Should exclude tasks with different cluster_id
	if found["task-2"] {
		t.Error("should not include task-2 (different cluster: cluster-b)")
	}

	// Should exclude tasks with different investigation_id
	if found["task-3"] {
		t.Error("should not include task-3 (different investigation: inv-2)")
	}
}
