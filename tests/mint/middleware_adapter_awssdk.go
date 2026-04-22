// middleware_adapter.go — Redirects bucket lifecycle operations through
// the S3 middleware admin API. Used when running Mint tests against the
// CloudStack S3 middleware (which denies bucket-admin ops at the proxy).
//
// Enable by setting MIDDLEWARE_ADMIN_URL, MIDDLEWARE_API_KEY, and
// MIDDLEWARE_ACCOUNT_ID environment variables.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

var (
	middlewareAdminURL  = os.Getenv("MIDDLEWARE_ADMIN_URL")
	middlewareAPIKey    = os.Getenv("MIDDLEWARE_API_KEY")
	middlewareAccountID = os.Getenv("MIDDLEWARE_ACCOUNT_ID")
	middlewareEnabled   = middlewareAdminURL != "" && middlewareAPIKey != "" && middlewareAccountID != ""
)

// createBucketViaAdmin calls the middleware admin API to create a bucket.
func createBucketViaAdmin(bucket string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"name":       bucket,
		"account_id": middlewareAccountID,
	})
	req, _ := http.NewRequest("POST", middlewareAdminURL+"/admin/buckets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+middlewareAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin API create bucket: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin API create bucket %s (%d): %s", bucket, resp.StatusCode, msg)
	}
	return nil
}

// deleteBucketViaAdmin calls the middleware admin API to delete a bucket.
func deleteBucketViaAdmin(bucket string) error {
	req, _ := http.NewRequest("DELETE", middlewareAdminURL+"/admin/buckets/"+bucket, nil)
	req.Header.Set("Authorization", "Bearer "+middlewareAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin API delete bucket: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

// setVersioningViaAdmin calls the middleware admin API to enable/suspend versioning.
func setVersioningViaAdmin(bucket string, enabled bool) error {
	body, _ := json.Marshal(map[string]bool{"enabled": enabled})
	req, _ := http.NewRequest("PUT", middlewareAdminURL+"/admin/buckets/"+bucket+"/versioning", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+middlewareAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("admin API set versioning: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin API set versioning %s (%d): %s", bucket, resp.StatusCode, msg)
	}
	return nil
}

// mwCreateBucket wraps CreateBucket — uses admin API if middleware is enabled.
func mwCreateBucket(ctx context.Context, s3Client *s3.Client, input *s3.CreateBucketInput) (*s3.CreateBucketOutput, error) {
	if middlewareEnabled {
		err := createBucketViaAdmin(*input.Bucket)
		return &s3.CreateBucketOutput{}, err
	}
	return s3Client.CreateBucket(ctx, input)
}

// mwDeleteBucket wraps DeleteBucket — uses admin API if middleware is enabled.
func mwDeleteBucket(ctx context.Context, s3Client *s3.Client, input *s3.DeleteBucketInput) (*s3.DeleteBucketOutput, error) {
	if middlewareEnabled {
		err := deleteBucketViaAdmin(*input.Bucket)
		return &s3.DeleteBucketOutput{}, err
	}
	return s3Client.DeleteBucket(ctx, input)
}

// mwPutBucketVersioning wraps PutBucketVersioning — uses admin API if middleware is enabled.
func mwPutBucketVersioning(ctx context.Context, s3Client *s3.Client, input *s3.PutBucketVersioningInput) (*s3.PutBucketVersioningOutput, error) {
	if middlewareEnabled {
		enabled := input.VersioningConfiguration != nil &&
			input.VersioningConfiguration.Status == s3types.BucketVersioningStatusEnabled
		err := setVersioningViaAdmin(*input.Bucket, enabled)
		return &s3.PutBucketVersioningOutput{}, err
	}
	return s3Client.PutBucketVersioning(ctx, input)
}

// Ensure unused imports are satisfied.
var _ = aws.String
