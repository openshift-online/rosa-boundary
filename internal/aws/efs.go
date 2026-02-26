package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/efs/types"
)

// AccessPointSummary holds minimal info about an EFS access point.
type AccessPointSummary struct {
	AccessPointID  string
	FileSystemID   string
	Path           string
	LifeCycleState string
	Tags           map[string]string
}

// EFSClient wraps the AWS EFS SDK client.
type EFSClient struct {
	client       *efs.Client
	filesystemID string
}

// NewEFSClient creates a new EFS client using the provided credentials provider.
func NewEFSClient(region, filesystemID string, credProvider aws.CredentialsProvider) *EFSClient {
	client := efs.New(efs.Options{
		Region:      region,
		Credentials: credProvider,
	})
	return &EFSClient{client: client, filesystemID: filesystemID}
}

// FindAccessPointByTags finds an available EFS access point by ClusterID and InvestigationID tags.
// Handles both "InvestigationID" and "InvestigationId" key variants.
// Returns nil if no matching access point is found.
func (c *EFSClient) FindAccessPointByTags(ctx context.Context, clusterID, investigationID string) (*AccessPointSummary, error) {
	paginator := efs.NewDescribeAccessPointsPaginator(c.client, &efs.DescribeAccessPointsInput{
		FileSystemId: aws.String(c.filesystemID),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeAccessPoints failed: %w", err)
		}
		for _, ap := range page.AccessPoints {
			if ap.LifeCycleState != types.LifeCycleStateAvailable {
				continue
			}
			tags := make(map[string]string)
			for _, tag := range ap.Tags {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			if tags["ClusterID"] == clusterID && tags["InvestigationID"] == investigationID {
				rootPath := ""
				if ap.RootDirectory != nil {
					rootPath = aws.ToString(ap.RootDirectory.Path)
				}
				return &AccessPointSummary{
					AccessPointID:  aws.ToString(ap.AccessPointId),
					FileSystemID:   aws.ToString(ap.FileSystemId),
					Path:           rootPath,
					LifeCycleState: string(ap.LifeCycleState),
					Tags:           tags,
				}, nil
			}
		}
	}
	return nil, nil
}

// ListInvestigations returns all EFS access points on the filesystem that have
// both ClusterID and InvestigationID tags (i.e. were created by rosa-boundary).
// If clusterID is non-empty, only access points matching that cluster are returned.
func (c *EFSClient) ListInvestigations(ctx context.Context, clusterID string) ([]AccessPointSummary, error) {
	var results []AccessPointSummary
	paginator := efs.NewDescribeAccessPointsPaginator(c.client, &efs.DescribeAccessPointsInput{
		FileSystemId: aws.String(c.filesystemID),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("DescribeAccessPoints failed: %w", err)
		}
		for _, ap := range page.AccessPoints {
			tags := make(map[string]string)
			for _, tag := range ap.Tags {
				tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
			}
			if tags["ClusterID"] == "" || tags["InvestigationID"] == "" {
				continue
			}
			if clusterID != "" && tags["ClusterID"] != clusterID {
				continue
			}
			rootPath := ""
			if ap.RootDirectory != nil {
				rootPath = aws.ToString(ap.RootDirectory.Path)
			}
			results = append(results, AccessPointSummary{
				AccessPointID:  aws.ToString(ap.AccessPointId),
				FileSystemID:   aws.ToString(ap.FileSystemId),
				Path:           rootPath,
				LifeCycleState: string(ap.LifeCycleState),
				Tags:           tags,
			})
		}
	}
	return results, nil
}

// DeleteAccessPoint deletes an EFS access point by ID.
func (c *EFSClient) DeleteAccessPoint(ctx context.Context, accessPointID string) error {
	_, err := c.client.DeleteAccessPoint(ctx, &efs.DeleteAccessPointInput{
		AccessPointId: aws.String(accessPointID),
	})
	if err != nil {
		return fmt.Errorf("DeleteAccessPoint failed: %w", err)
	}
	return nil
}
