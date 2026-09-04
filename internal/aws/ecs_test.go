package aws

import (
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
