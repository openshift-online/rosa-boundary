package aws

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestCloseReceiptFetch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/audit/_boundary-close/fsap-1/seal.json" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "123456789012" {
			t.Errorf("unexpected receipt request %s %s owner=%s", r.Method, r.URL.Path, r.Header.Get("X-Amz-Expected-Bucket-Owner"))
		}
		if _, err := fmt.Fprint(w, "receipt"); err != nil {
			t.Errorf("write test receipt: %v", err)
		}
	}))
	defer srv.Close()
	reader := CloseReceiptReader{s3.New(s3.Options{Region: "us-east-1", BaseEndpoint: aws.String(srv.URL), UsePathStyle: true, Credentials: credentials.NewStaticCredentialsProvider("test", "test", "")}), "123456789012"}
	b, err := reader.Read(context.Background(), "audit", "fsap-1", "seal")
	if err != nil || string(b) != "receipt" {
		t.Fatalf("body=%q err=%v", b, err)
	}
}

func TestCloseReceiptBound(t *testing.T) {
	for _, size := range []int{16384, 16385} {
		_, err := readReceiptBody(strings.NewReader(strings.Repeat("x", size)))
		if (err != nil) != (size > 16384) {
			t.Fatalf("size %d err=%v", size, err)
		}
	}
}
