package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/efs/types"
)

// mockEFSClient is a mock EFS client for testing
type mockEFSClient struct {
	accessPoints []types.AccessPointDescription
}

func (m *mockEFSClient) DescribeAccessPoints(ctx context.Context, params *efs.DescribeAccessPointsInput, optFns ...func(*efs.Options)) (*efs.DescribeAccessPointsOutput, error) {
	return &efs.DescribeAccessPointsOutput{
		AccessPoints: m.accessPoints,
	}, nil
}

func (m *mockEFSClient) DeleteAccessPoint(ctx context.Context, params *efs.DeleteAccessPointInput, optFns ...func(*efs.Options)) (*efs.DeleteAccessPointOutput, error) {
	return &efs.DeleteAccessPointOutput{}, nil
}

func TestFindAccessPointByTags_WithClusterID(t *testing.T) {
	mock := &mockEFSClient{
		accessPoints: []types.AccessPointDescription{
			{
				AccessPointId:  aws.String("fsap-111"),
				FileSystemId:   aws.String("fs-test"),
				LifeCycleState: types.LifeCycleStateAvailable,
				RootDirectory:  &types.RootDirectory{Path: aws.String("/cluster1/inv1")},
				Tags: []types.Tag{
					{Key: aws.String("ClusterID"), Value: aws.String("cluster1")},
					{Key: aws.String("InvestigationID"), Value: aws.String("inv1")},
				},
			},
			{
				AccessPointId:  aws.String("fsap-222"),
				FileSystemId:   aws.String("fs-test"),
				LifeCycleState: types.LifeCycleStateAvailable,
				RootDirectory:  &types.RootDirectory{Path: aws.String("/cluster2/inv1")},
				Tags: []types.Tag{
					{Key: aws.String("ClusterID"), Value: aws.String("cluster2")},
					{Key: aws.String("InvestigationID"), Value: aws.String("inv1")},
				},
			},
		},
	}

	client := &EFSClient{client: mock, filesystemID: "fs-test"}

	// Should find only cluster1's access point
	ap, err := client.FindAccessPointByTags(context.Background(), "cluster1", "inv1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap == nil {
		t.Fatal("expected access point, got nil")
	}
	if ap.AccessPointID != "fsap-111" {
		t.Errorf("got access point %s, want fsap-111", ap.AccessPointID)
	}
	if ap.Tags["ClusterID"] != "cluster1" {
		t.Errorf("got cluster %s, want cluster1", ap.Tags["ClusterID"])
	}
}

func TestFindAccessPointByTags_WithoutClusterID_Unique(t *testing.T) {
	mock := &mockEFSClient{
		accessPoints: []types.AccessPointDescription{
			{
				AccessPointId:  aws.String("fsap-111"),
				FileSystemId:   aws.String("fs-test"),
				LifeCycleState: types.LifeCycleStateAvailable,
				RootDirectory:  &types.RootDirectory{Path: aws.String("/cluster1/unique-inv")},
				Tags: []types.Tag{
					{Key: aws.String("ClusterID"), Value: aws.String("cluster1")},
					{Key: aws.String("InvestigationID"), Value: aws.String("unique-inv")},
				},
			},
		},
	}

	client := &EFSClient{client: mock, filesystemID: "fs-test"}

	// Should find the access point without cluster ID since it's unique
	ap, err := client.FindAccessPointByTags(context.Background(), "", "unique-inv")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap == nil {
		t.Fatal("expected access point, got nil")
	}
	if ap.AccessPointID != "fsap-111" {
		t.Errorf("got access point %s, want fsap-111", ap.AccessPointID)
	}
}

func TestFindAccessPointByTags_WithoutClusterID_Ambiguous(t *testing.T) {
	mock := &mockEFSClient{
		accessPoints: []types.AccessPointDescription{
			{
				AccessPointId:  aws.String("fsap-111"),
				FileSystemId:   aws.String("fs-test"),
				LifeCycleState: types.LifeCycleStateAvailable,
				RootDirectory:  &types.RootDirectory{Path: aws.String("/cluster1/inv1")},
				Tags: []types.Tag{
					{Key: aws.String("ClusterID"), Value: aws.String("cluster1")},
					{Key: aws.String("InvestigationID"), Value: aws.String("inv1")},
				},
			},
			{
				AccessPointId:  aws.String("fsap-222"),
				FileSystemId:   aws.String("fs-test"),
				LifeCycleState: types.LifeCycleStateAvailable,
				RootDirectory:  &types.RootDirectory{Path: aws.String("/cluster2/inv1")},
				Tags: []types.Tag{
					{Key: aws.String("ClusterID"), Value: aws.String("cluster2")},
					{Key: aws.String("InvestigationID"), Value: aws.String("inv1")},
				},
			},
		},
	}

	client := &EFSClient{client: mock, filesystemID: "fs-test"}

	// Should error due to ambiguity
	ap, err := client.FindAccessPointByTags(context.Background(), "", "inv1")
	if err == nil {
		t.Fatal("expected error for ambiguous investigation ID, got nil")
	}
	if ap != nil {
		t.Errorf("expected nil access point on error, got %+v", ap)
	}

	// Error message should mention both clusters
	errMsg := err.Error()
	if !contains(errMsg, "ambiguous") {
		t.Errorf("error message should mention 'ambiguous', got: %s", errMsg)
	}
	if !contains(errMsg, "cluster1") || !contains(errMsg, "cluster2") {
		t.Errorf("error message should list both cluster IDs, got: %s", errMsg)
	}
}

func TestFindAccessPointByTags_NotFound(t *testing.T) {
	mock := &mockEFSClient{
		accessPoints: []types.AccessPointDescription{},
	}

	client := &EFSClient{client: mock, filesystemID: "fs-test"}

	ap, err := client.FindAccessPointByTags(context.Background(), "cluster1", "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap != nil {
		t.Errorf("expected nil for not found, got %+v", ap)
	}
}

func TestFindAccessPointByTags_SkipsNonAvailable(t *testing.T) {
	mock := &mockEFSClient{
		accessPoints: []types.AccessPointDescription{
			{
				AccessPointId:  aws.String("fsap-deleting"),
				FileSystemId:   aws.String("fs-test"),
				LifeCycleState: types.LifeCycleStateDeleting,
				Tags: []types.Tag{
					{Key: aws.String("ClusterID"), Value: aws.String("cluster1")},
					{Key: aws.String("InvestigationID"), Value: aws.String("inv1")},
				},
			},
			{
				AccessPointId:  aws.String("fsap-available"),
				FileSystemId:   aws.String("fs-test"),
				LifeCycleState: types.LifeCycleStateAvailable,
				Tags: []types.Tag{
					{Key: aws.String("ClusterID"), Value: aws.String("cluster1")},
					{Key: aws.String("InvestigationID"), Value: aws.String("inv1")},
				},
			},
		},
	}

	client := &EFSClient{client: mock, filesystemID: "fs-test"}

	ap, err := client.FindAccessPointByTags(context.Background(), "cluster1", "inv1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ap == nil {
		t.Fatal("expected access point, got nil")
	}
	if ap.AccessPointID != "fsap-available" {
		t.Errorf("got access point %s, want fsap-available (should skip deleting state)", ap.AccessPointID)
	}
}

// contains checks if a string contains a substring (case-sensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
