package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type s3ProxyHandler struct {
	db     *DB
	awsCfg *AWSConfig
	cache  *CredCache
	client *http.Client
}

func newS3ProxyHandler(db *DB, awsCfg *AWSConfig, cache *CredCache) http.Handler {
	return &s3ProxyHandler{
		db:     db,
		awsCfg: awsCfg,
		cache:  cache,
		client: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *s3ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Buffer entire request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadGateway)
		return
	}
	defer r.Body.Close()

	// 2. Verify customer's SigV4
	accessKey, err := verifySigV4(r, body, h.db)
	if err != nil {
		log.Printf("S3 proxy auth failed: %v", err)
		http.Error(w, "SignatureDoesNotMatch", http.StatusForbidden)
		return
	}

	// 3. Get account and scoped AWS credentials
	account, err := h.db.GetAccountByAccessKey(accessKey)
	if err != nil || account == nil {
		http.Error(w, "Account not found", http.StatusForbidden)
		return
	}

	scopedCreds, err := h.getOrAssumeRole(accessKey, account.ID)
	if err != nil {
		log.Printf("AssumeRole failed for %s: %v", accessKey, err)
		http.Error(w, "Failed to obtain credentials", http.StatusInternalServerError)
		return
	}

	// 4. [fixup] Decode aws-chunked body if present
	var trailingHeaders map[string]string
	contentSha := r.Header.Get("X-Amz-Content-Sha256")
	if strings.HasPrefix(contentSha, "STREAMING-") {
		decoded, trailers, decErr := decodeAWSChunked(body)
		if decErr != nil {
			log.Printf("[fixup] aws-chunked decode error: %v", decErr)
			http.Error(w, "Failed to decode chunked body", http.StatusBadRequest)
			return
		}
		body = decoded
		trailingHeaders = trailers
		log.Printf("[fixup] decoded aws-chunked: %d bytes, %d trailers", len(decoded), len(trailers))
	}

	// 5. [fixup] CreateBucket LocationConstraint injection
	isCreate := isCreateBucket(r)
	var deferredACL string
	if isCreate && needsLocationConstraint(body, h.awsCfg.Region) {
		body = []byte(fmt.Sprintf(
			`<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>%s</LocationConstraint></CreateBucketConfiguration>`,
			h.awsCfg.Region))
		log.Printf("[fixup] injected LocationConstraint=%s", h.awsCfg.Region)
	}

	// 6. Build forwarding request
	targetURL := fmt.Sprintf("https://s3.%s.amazonaws.com%s", h.awsCfg.Region, r.URL.RequestURI())
	proxyReq, err := http.NewRequest(r.Method, targetURL, bytes.NewReader(body))
	if err != nil {
		http.Error(w, "Failed to create request", http.StatusInternalServerError)
		return
	}

	// 7. Copy headers with filters
	skipHeaders := map[string]bool{
		"Authorization":         true,
		"Host":                  true,
		"X-Amz-Date":           true,
		"X-Amz-Security-Token":  true,
		"X-Amz-Content-Sha256":  true,
		"Content-Length":        true,
		"Trailer":              true,
		"X-Amz-Trailer":        true,
	}
	for key, vals := range r.Header {
		if skipHeaders[key] {
			continue
		}
		// [fixup] Defer ACL on CreateBucket
		if isCreate && strings.EqualFold(key, "X-Amz-Acl") {
			deferredACL = vals[0]
			log.Printf("[fixup] deferred ACL '%s' for post-create", deferredACL)
			continue
		}
		for _, v := range vals {
			proxyReq.Header.Add(key, v)
		}
	}

	// [fixup] Add Object-Ownership header on CreateBucket
	if isCreate {
		proxyReq.Header.Set("X-Amz-Object-Ownership", "BucketOwnerPreferred")
	}

	// Promote trailing headers (from HTTP Trailer)
	for key, vals := range r.Trailer {
		for _, v := range vals {
			proxyReq.Header.Set(key, v)
		}
	}

	// Promote trailing headers (from aws-chunked decode)
	if trailingHeaders != nil {
		for k, v := range trailingHeaders {
			proxyReq.Header.Set(k, v)
		}
	}

	// 8. [fixup] Sign with scoped credentials
	// Strip aws-chunked from Content-Encoding
	if ce := proxyReq.Header.Get("Content-Encoding"); ce != "" {
		var filtered []string
		for _, p := range strings.Split(ce, ",") {
			p = strings.TrimSpace(p)
			if p != "aws-chunked" {
				filtered = append(filtered, p)
			}
		}
		if len(filtered) > 0 {
			proxyReq.Header.Set("Content-Encoding", strings.Join(filtered, ","))
		} else {
			proxyReq.Header.Del("Content-Encoding")
		}
	}

	// [fixup] Compute real SHA256 for SSE-C requests, otherwise UNSIGNED-PAYLOAD
	payloadHash := "UNSIGNED-PAYLOAD"
	if proxyReq.Header.Get("X-Amz-Server-Side-Encryption-Customer-Algorithm") != "" {
		h256 := sha256.Sum256(body)
		payloadHash = hex.EncodeToString(h256[:])
	}

	signer := v4signer.NewSigner(func(o *v4signer.SignerOptions) {
		o.DisableURIPathEscaping = true // [fixup] S3 does not double-encode paths
	})

	awsCreds := credentials.NewStaticCredentialsProvider(
		scopedCreds.AccessKeyID, scopedCreds.SecretAccessKey, scopedCreds.SessionToken,
	)
	sigCreds, _ := awsCreds.Retrieve(context.Background())

	proxyReq.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	proxyReq.ContentLength = int64(len(body))

	err = signer.SignHTTP(context.Background(), sigCreds, proxyReq, payloadHash, "s3", h.awsCfg.Region, time.Now())
	if err != nil {
		log.Printf("SignHTTP failed: %v", err)
		http.Error(w, "Failed to sign request", http.StatusInternalServerError)
		return
	}

	// 9. Forward to AWS S3
	resp, err := h.client.Do(proxyReq)
	if err != nil {
		log.Printf("Upstream request failed: %v", err)
		http.Error(w, "Upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// [fixup] Bypass-governance-retention retry
	if resp.StatusCode == 400 && strings.Contains(string(respBody), "x-amz-bypass-governance-retention") {
		log.Printf("[fixup] retrying without x-amz-bypass-governance-retention")
		proxyReq2, _ := http.NewRequest(r.Method, targetURL, bytes.NewReader(body))
		for key, vals := range proxyReq.Header {
			if strings.EqualFold(key, "X-Amz-Bypass-Governance-Retention") {
				continue
			}
			proxyReq2.Header[key] = vals
		}
		proxyReq2.Header.Del("X-Amz-Bypass-Governance-Retention")
		proxyReq2.ContentLength = int64(len(body))

		err = signer.SignHTTP(context.Background(), sigCreds, proxyReq2, payloadHash, "s3", h.awsCfg.Region, time.Now())
		if err == nil {
			resp2, err2 := h.client.Do(proxyReq2)
			if err2 == nil {
				respBody, _ = io.ReadAll(resp2.Body)
				resp2.Body.Close()
				resp = resp2
			}
		}
	}

	// 10. [fixup] Copy response headers, lowercasing x-amz-*
	for key, vals := range resp.Header {
		outKey := key
		if strings.HasPrefix(key, "X-Amz-") {
			outKey = strings.ToLower(key)
		}
		for _, v := range vals {
			w.Header().Add(outKey, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	// 11. [fixup] Post-CreateBucket fixups
	if isCreate && resp.StatusCode == 200 {
		bucket := extractBucketName(r)
		if bucket != "" {
			go h.postCreateBucketFixups(bucket, deferredACL)
		}
	}
}

// getOrAssumeRole gets cached STS credentials or calls AssumeRole.
func (h *s3ProxyHandler) getOrAssumeRole(accessKey string, accountID string) (aws.Credentials, error) {
	if cached, ok := h.cache.get(accessKey); ok {
		return cached.creds, nil
	}

	buckets, err := h.db.ListBucketsByAccount(accountID)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("list buckets: %w", err)
	}

	sessionPolicy := buildSessionPolicy(buckets)

	stsClient := sts.New(sts.Options{
		Region:      h.awsCfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(h.awsCfg.AccessKey, h.awsCfg.SecretKey, ""),
	})

	result, err := stsClient.AssumeRole(context.Background(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(h.awsCfg.RoleARN),
		RoleSessionName: aws.String(fmt.Sprintf("s3mw-%s-%d", accessKey[:min(10, len(accessKey))], time.Now().Unix())),
		Policy:          aws.String(sessionPolicy),
		DurationSeconds: aws.Int32(3600),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("assume role: %w", err)
	}

	c := result.Credentials
	creds := aws.Credentials{
		AccessKeyID:     *c.AccessKeyId,
		SecretAccessKey: *c.SecretAccessKey,
		SessionToken:    *c.SessionToken,
	}
	h.cache.set(accessKey, creds, *c.Expiration)
	return creds, nil
}

// postCreateBucketFixups runs after a successful CreateBucket via the proxy.
// Uses the service account credentials (not scoped) for admin operations.
func (h *s3ProxyHandler) postCreateBucketFixups(bucket, deferredACL string) {
	client := s3.New(s3.Options{
		Region:      h.awsCfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(h.awsCfg.AccessKey, h.awsCfg.SecretKey, ""),
	})
	ctx := context.Background()

	// 1. Disable Block Public Access
	_, err := client.DeletePublicAccessBlock(ctx, &s3.DeletePublicAccessBlockInput{
		Bucket: aws.String(bucket),
	})
	if err != nil {
		log.Printf("[fixup] warning: failed to disable Block Public Access on %s: %v", bucket, err)
	} else {
		log.Printf("[fixup] disabled Block Public Access on %s", bucket)
	}

	// 2. Enable ACLs (BucketOwnerPreferred)
	_, err = client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
		Bucket: aws.String(bucket),
		OwnershipControls: &s3types.OwnershipControls{
			Rules: []s3types.OwnershipControlsRule{
				{ObjectOwnership: s3types.ObjectOwnershipBucketOwnerPreferred},
			},
		},
	})
	if err != nil {
		log.Printf("[fixup] warning: failed to enable ACLs on %s: %v", bucket, err)
	} else {
		log.Printf("[fixup] enabled ACLs (BucketOwnerPreferred) on %s", bucket)
	}

	// 3. Re-apply deferred ACL
	if deferredACL != "" {
		_, err = client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket: aws.String(bucket),
			ACL:    s3types.BucketCannedACL(deferredACL),
		})
		if err != nil {
			log.Printf("[fixup] warning: failed to apply deferred ACL '%s' on %s: %v", deferredACL, bucket, err)
		} else {
			log.Printf("[fixup] applied deferred ACL '%s' on %s", deferredACL, bucket)
		}
	}
}

// isCreateBucket detects PUT to a bare bucket path (no object key).
func isCreateBucket(r *http.Request) bool {
	if r.Method != "PUT" {
		return false
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		return false
	}
	if strings.Contains(path, "/") {
		return false
	}
	q := r.URL.RawQuery
	if q == "" {
		return true
	}
	nonCreateParams := []string{"acl", "policy", "tagging", "versioning", "lifecycle",
		"cors", "encryption", "logging", "replication", "object-lock",
		"notification", "uploads", "delete", "ownership", "publicAccessBlock"}
	for _, p := range nonCreateParams {
		if strings.Contains(q, p) {
			return false
		}
	}
	return true
}

func needsLocationConstraint(body []byte, region string) bool {
	if region == "us-east-1" {
		return false
	}
	return len(body) == 0 || !strings.Contains(string(body), "LocationConstraint")
}

func extractBucketName(r *http.Request) string {
	path := strings.TrimPrefix(r.URL.Path, "/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// decodeAWSChunked decodes aws-chunked transfer encoding.
// Returns the decoded payload and any trailing headers.
func decodeAWSChunked(data []byte) ([]byte, map[string]string, error) {
	var payload []byte
	trailers := make(map[string]string)
	remaining := data

	for {
		idx := bytes.Index(remaining, []byte("\r\n"))
		if idx < 0 {
			break
		}
		headerLine := string(remaining[:idx])
		remaining = remaining[idx+2:]

		sizeStr := headerLine
		if semi := strings.Index(headerLine, ";"); semi >= 0 {
			sizeStr = headerLine[:semi]
		}
		chunkSize, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 16, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid chunk size: %s", sizeStr)
		}

		if chunkSize == 0 {
			for {
				idx = bytes.Index(remaining, []byte("\r\n"))
				if idx < 0 || idx == 0 {
					break
				}
				line := string(remaining[:idx])
				remaining = remaining[idx+2:]
				if colon := strings.Index(line, ":"); colon > 0 {
					key := strings.TrimSpace(line[:colon])
					val := strings.TrimSpace(line[colon+1:])
					if strings.EqualFold(key, "x-amz-trailer-signature") {
						continue
					}
					trailers[key] = val
				}
			}
			break
		}

		if int64(len(remaining)) < chunkSize+2 {
			return nil, nil, fmt.Errorf("truncated chunk data")
		}
		payload = append(payload, remaining[:chunkSize]...)
		remaining = remaining[chunkSize+2:]
	}

	return payload, trailers, nil
}
