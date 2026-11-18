package aws

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// CloseReceiptReader fetches only the operator's exact sealed receipt, never task output.
type CloseReceiptReader struct {
	client    *s3.Client
	accountID string
}

func NewCloseReceiptReader(region, accountID string, credentials aws.CredentialsProvider) *CloseReceiptReader {
	endpoint := integrationEndpoint()
	return &CloseReceiptReader{s3.New(s3.Options{Region: region, Credentials: credentials, BaseEndpoint: endpoint, UsePathStyle: endpoint != nil}), accountID}
}

func (r *CloseReceiptReader) Read(ctx context.Context, bucket, ap, seal string) ([]byte, error) {
	if r.accountID == "" {
		return nil, fmt.Errorf("expected audit bucket owner is not configured")
	}
	out, err := r.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String("_boundary-close/" + ap + "/" + seal + ".json"), ExpectedBucketOwner: aws.String(r.accountID)})
	if err != nil {
		return nil, err
	}
	body, readErr := readReceiptBody(out.Body)
	if err := errors.Join(readErr, out.Body.Close()); err != nil {
		return nil, err
	}
	return body, nil
}

func readReceiptBody(r io.Reader) ([]byte, error) {
	const maxSize = 16 << 10
	b, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if len(b) > maxSize {
		return nil, fmt.Errorf("close receipt exceeds %d bytes", maxSize)
	}
	return b, err
}
