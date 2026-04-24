package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	s3svc "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	stssvc "github.com/aws/aws-sdk-go-v2/service/sts"
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
		client: &http.Client{Timeout: 5 * time.Minute},
	}
}

// getScopedCreds returns AWS credentials scoped to a customer's buckets via
// AssumeRole + session policy. Results are cached until near-expiry.
func (h *s3ProxyHandler) getScopedCreds(ctx context.Context, accessKey string) (aws.Credentials, error) {
	if cached, ok := h.cache.get(accessKey); ok {
		return cached.creds, nil
	}

	account, err := h.db.GetAccountByAccessKey(accessKey)
	if err != nil || account == nil {
		return aws.Credentials{}, fmt.Errorf("account not found for key: %s", accessKey)
	}

	sessionPolicy := buildSessionPolicy(account.Name)

	stsClient := stssvc.New(stssvc.Options{
		Region:      h.awsCfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(h.awsCfg.AccessKey, h.awsCfg.SecretKey, ""),
	})
	result, err := stsClient.AssumeRole(ctx, &stssvc.AssumeRoleInput{
		RoleArn:         aws.String(h.awsCfg.RoleARN),
		RoleSessionName: aws.String(fmt.Sprintf("proxy-%s-%d", accessKey[:min(10, len(accessKey))], time.Now().Unix())),
		Policy:          aws.String(sessionPolicy),
		DurationSeconds: aws.Int32(3600),
	})
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("AssumeRole: %w", err)
	}

	scopedCreds := aws.Credentials{
		AccessKeyID:     *result.Credentials.AccessKeyId,
		SecretAccessKey: *result.Credentials.SecretAccessKey,
		SessionToken:    *result.Credentials.SessionToken,
	}
	h.cache.set(accessKey, scopedCreds, *result.Credentials.Expiration)

	log.Printf("  [cache] issued scoped creds for %s (expires %s, prefix: %s*)",
		accessKey[:min(10, len(accessKey))], result.Credentials.Expiration.Format(time.RFC3339), account.Name)

	return scopedCreds, nil
}

func (h *s3ProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Buffer the body (needed for Sig V4 verification and CreateBucket fixup)
	var body []byte
	if r.Body != nil {
		var err error
		body, err = io.ReadAll(r.Body)
		if err != nil {
			s3Error(w, "InternalError", "Failed to read body", http.StatusBadRequest)
			return
		}
		r.Body.Close()
	}

	// 2. Verify customer's Sig V4
	accessKey, err := verifySigV4(r, body, h.db)
	if err != nil {
		log.Printf("AUTH FAIL [%s %s]: %v", r.Method, r.URL.Path, err)
		s3Error(w, "SignatureDoesNotMatch", err.Error(), http.StatusForbidden)
		return
	}
	log.Printf("[%s] %s %s%s", accessKey[:min(10, len(accessKey))], r.Method, r.URL.Path, querySnippet(r))

	// 3. Get scoped credentials for this customer (AssumeRole + session policy)
	creds, err := h.getScopedCreds(r.Context(), accessKey)
	if err != nil {
		log.Printf("  getScopedCreds failed: %v", err)
		s3Error(w, "InternalError", "Credential error", http.StatusBadGateway)
		return
	}

	// 3a. Decode aws-chunked body if present.
	// When x-amz-content-sha256 is STREAMING-AWS4-HMAC-SHA256-PAYLOAD,
	// the body uses aws-chunked encoding with per-chunk signatures.
	// Decode it to extract the actual payload data.
	var awsChunkedTrailers map[string]string
	if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
		decoded, trailers, err := decodeAWSChunked(body)
		if err != nil {
			log.Printf("  aws-chunked decode error: %v", err)
			s3Error(w, "InternalError", "Failed to decode chunked body", http.StatusBadRequest)
			return
		}
		body = decoded
		awsChunkedTrailers = trailers
		if len(trailers) > 0 {
			log.Printf("  [aws-chunked] extracted trailers: %v", trailers)
		}
	}

	// 4. Fixup: inject LocationConstraint for CreateBucket if missing.
	//    CreateBucket = PUT to a bare bucket path (e.g. PUT /my-bucket)
	//    with no query string or only specific bucket-level query params.
	forwardBody := body
	if r.Method == http.MethodPut && isCreateBucket(r) && needsLocationConstraint(body, h.awsCfg.Region) {
		forwardBody = []byte(fmt.Sprintf(
			`<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>%s</LocationConstraint></CreateBucketConfiguration>`,
			h.awsCfg.Region))
		log.Printf("  [fixup] injected LocationConstraint=%s", h.awsCfg.Region)
	}

	// 5. Build forwarding request to real S3
	target := fmt.Sprintf("https://s3.%s.amazonaws.com%s",
		h.awsCfg.Region, r.URL.RequestURI())
	proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, target,
		bytes.NewReader(forwardBody))
	if err != nil {
		s3Error(w, "InternalError", "Failed to build upstream request", http.StatusBadGateway)
		return
	}
	proxyReq.ContentLength = int64(len(forwardBody))

	// Copy non-auth headers, stripping auth headers and headers
	// incompatible with plain S3 (no Object Lock on these buckets)
	isCreate := r.Method == http.MethodPut && isCreateBucket(r)
	var deferredACL string // ACL to re-apply after CreateBucket setup
	for key, vals := range r.Header {
		lk := strings.ToLower(key)
		switch {
		case lk == "authorization", lk == "host", lk == "x-amz-date",
			lk == "x-amz-security-token", lk == "x-amz-content-sha256",
			lk == "content-length",
			lk == "trailer", lk == "x-amz-trailer":
			// Strip Trailer/x-amz-trailer — the proxy buffers the full body
			// and promotes trailing checksums to regular headers below.
			continue
		case isCreate && lk == "x-amz-acl":
			// Strip ACL from CreateBucket — bucket-level Block Public Access
			// is still active at creation time. We'll re-apply after setup.
			deferredACL = vals[0]
			log.Printf("  [fixup] deferred ACL '%s' for post-create", deferredACL)
			continue
		default:
			proxyReq.Header[key] = vals
		}
	}

	// Promote trailing checksums to regular headers on the forwarded request.
	// Sources: HTTP trailers (r.Trailer) and aws-chunked trailing headers.
	for key, vals := range r.Trailer {
		proxyReq.Header[key] = vals
	}
	for key, val := range awsChunkedTrailers {
		proxyReq.Header.Set(key, val)
	}

	// Inject ObjectOwnership header on CreateBucket so ACLs work from the start
	if isCreate {
		proxyReq.Header.Set("X-Amz-Object-Ownership", "BucketOwnerPreferred")
	}

	// 6. Sign with SCOPED credentials.
	// DisableURIPathEscaping is required for S3 — the path is already
	// correctly encoded, and S3 does not double-encode like other AWS services.
	signer := v4signer.NewSigner(func(o *v4signer.SignerOptions) {
		o.DisableURIPathEscaping = true
	})

	// Strip aws-chunked from Content-Encoding — the proxy has already
	// buffered the full body, so chunked transfer encoding is resolved.
	// AWS strips aws-chunked from stored Content-Encoding; we do the same.
	if ce := proxyReq.Header.Get("Content-Encoding"); strings.Contains(strings.ToLower(ce), "aws-chunked") {
		parts := strings.Split(ce, ",")
		var kept []string
		for _, p := range parts {
			if strings.TrimSpace(strings.ToLower(p)) != "aws-chunked" {
				kept = append(kept, strings.TrimSpace(p))
			}
		}
		if len(kept) > 0 {
			proxyReq.Header.Set("Content-Encoding", strings.Join(kept, ", "))
		} else {
			proxyReq.Header.Del("Content-Encoding")
		}
	}

	// AWS requires a real content hash (not UNSIGNED-PAYLOAD) when SSE-C
	// headers are present. Compute SHA256 of the body for those requests.
	payloadHash := "UNSIGNED-PAYLOAD"
	if proxyReq.Header.Get("X-Amz-Server-Side-Encryption-Customer-Algorithm") != "" {
		h := sha256.Sum256(forwardBody)
		payloadHash = hex.EncodeToString(h[:])
	}
	proxyReq.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if err := signer.SignHTTP(r.Context(), creds, proxyReq,
		payloadHash, "s3", h.awsCfg.Region, time.Now()); err != nil {
		log.Printf("Signing failed: %v", err)
		s3Error(w, "InternalError", "Signing error", http.StatusBadGateway)
		return
	}

	// 7. Forward to AWS
	resp, err := h.client.Do(proxyReq)
	if err != nil {
		log.Printf("Upstream error: %v", err)
		s3Error(w, "InternalError", "Upstream unreachable", http.StatusBadGateway)
		return
	}

	// 7a. If AWS rejects x-amz-bypass-governance-retention on a
	// non-Object-Lock bucket, retry without it. The test suite sends
	// this header on all DeleteObjects calls; AWS only accepts it on
	// Object Lock buckets.
	if resp.StatusCode == 400 {
		peekBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(string(peekBody), "x-amz-bypass-governance-retention") {
			log.Printf("  [retry] stripping x-amz-bypass-governance-retention")
			retryReq, _ := http.NewRequestWithContext(r.Context(), r.Method, target,
				bytes.NewReader(forwardBody))
			retryReq.ContentLength = int64(len(forwardBody))
			for key, vals := range r.Header {
				lk := strings.ToLower(key)
				switch {
				case lk == "authorization", lk == "host", lk == "x-amz-date",
					lk == "x-amz-security-token", lk == "x-amz-content-sha256",
					lk == "content-length",
					lk == "x-amz-bypass-governance-retention":
					continue
				default:
					retryReq.Header[key] = vals
				}
			}
			retrySigner := v4signer.NewSigner(func(o *v4signer.SignerOptions) {
				o.DisableURIPathEscaping = true
			})
			retryReq.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
			retrySigner.SignHTTP(r.Context(), creds, retryReq,
				"UNSIGNED-PAYLOAD", "s3", h.awsCfg.Region, time.Now())
			resp, err = h.client.Do(retryReq)
			if err != nil {
				log.Printf("Retry upstream error: %v", err)
				s3Error(w, "InternalError", "Upstream unreachable", http.StatusBadGateway)
				return
			}
		} else {
			// Not the bypass error — restore body for response
			resp.Body = io.NopCloser(bytes.NewReader(peekBody))
		}
	}
	defer resp.Body.Close()

	// 8. Return response — lowercase x-amz-* headers to preserve the
	// casing AWS sends. Go's HTTP client canonicalizes to Title-Case
	// which breaks boto3 and other SDKs that expect lowercase.
	for key, vals := range resp.Header {
		outKey := key
		if strings.HasPrefix(key, "X-Amz-") {
			outKey = strings.ToLower(key)
		}
		w.Header()[outKey] = vals
	}
	w.WriteHeader(resp.StatusCode)

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		w.Write(respBody)
		errSnippet := string(respBody)
		if len(errSnippet) > 300 {
			errSnippet = errSnippet[:300]
		}
		log.Printf("  -> %d  %s", resp.StatusCode, errSnippet)
	} else {
		io.Copy(w, resp.Body)
		log.Printf("  -> %d", resp.StatusCode)

		// After a successful CreateBucket, disable Block Public Access,
		// enable ACLs, and re-apply any deferred ACL
		if r.Method == http.MethodPut && isCreateBucket(r) && resp.StatusCode == 200 {
			bucketName := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/")
			h.disableBucketPublicAccessBlock(creds, bucketName)
			h.enableBucketACLs(creds, bucketName)
			if deferredACL != "" {
				h.applyBucketACL(creds, bucketName, deferredACL)
			}
		}
	}
}

// disableBucketPublicAccessBlock removes the Block Public Access settings
// from a newly created bucket so that ACL and policy tests work on AWS.
func (h *s3ProxyHandler) disableBucketPublicAccessBlock(creds aws.Credentials, bucket string) {
	s3Client := s3svc.New(s3svc.Options{
		Region: h.awsCfg.Region,
		Credentials: aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) { return creds, nil },
		),
	})
	_, err := s3Client.DeletePublicAccessBlock(context.Background(),
		&s3svc.DeletePublicAccessBlockInput{Bucket: aws.String(bucket)})
	if err != nil {
		log.Printf("  [fixup] failed to disable Block Public Access on %s: %v", bucket, err)
	} else {
		log.Printf("  [fixup] disabled Block Public Access on %s", bucket)
	}
}

// enableBucketACLs sets ObjectOwnership to BucketOwnerPreferred so that
// ACL operations (PutObjectAcl, canned ACLs on PUT, etc.) are accepted.
// Since April 2023, new S3 buckets default to BucketOwnerEnforced which
// disables ACLs entirely.
func (h *s3ProxyHandler) enableBucketACLs(creds aws.Credentials, bucket string) {
	s3Client := s3svc.New(s3svc.Options{
		Region: h.awsCfg.Region,
		Credentials: aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) { return creds, nil },
		),
	})
	_, err := s3Client.PutBucketOwnershipControls(context.Background(),
		&s3svc.PutBucketOwnershipControlsInput{
			Bucket: aws.String(bucket),
			OwnershipControls: &s3types.OwnershipControls{
				Rules: []s3types.OwnershipControlsRule{
					{ObjectOwnership: s3types.ObjectOwnershipBucketOwnerPreferred},
				},
			},
		})
	if err != nil {
		log.Printf("  [fixup] failed to enable ACLs on %s: %v", bucket, err)
	} else {
		log.Printf("  [fixup] enabled ACLs (BucketOwnerPreferred) on %s", bucket)
	}
}

// applyBucketACL sets a canned ACL on a bucket after Block Public Access
// has been disabled. This handles the case where CreateBucket was called
// with x-amz-acl but the ACL had to be deferred.
func (h *s3ProxyHandler) applyBucketACL(creds aws.Credentials, bucket, acl string) {
	s3Client := s3svc.New(s3svc.Options{
		Region: h.awsCfg.Region,
		Credentials: aws.CredentialsProviderFunc(
			func(ctx context.Context) (aws.Credentials, error) { return creds, nil },
		),
	})
	_, err := s3Client.PutBucketAcl(context.Background(),
		&s3svc.PutBucketAclInput{
			Bucket: aws.String(bucket),
			ACL:    s3types.BucketCannedACL(acl),
		})
	if err != nil {
		log.Printf("  [fixup] failed to apply ACL '%s' on %s: %v", acl, bucket, err)
	} else {
		log.Printf("  [fixup] applied ACL '%s' on %s", acl, bucket)
	}
}

// decodeAWSChunked decodes an aws-chunked encoded body and extracts any
// trailing headers (e.g. x-amz-checksum-crc32c). Returns the decoded
// payload and a map of trailing headers.
// Format: hex-size;chunk-signature=...\r\nchunk-data\r\n ...
//
//	0;chunk-signature=...\r\n
//	trailing-header:value\r\n
//	x-amz-trailer-signature:...\r\n
//	\r\n
func decodeAWSChunked(data []byte) ([]byte, map[string]string, error) {
	var result []byte
	remaining := data
	for {
		// Find end of chunk header line
		idx := bytes.Index(remaining, []byte("\r\n"))
		if idx < 0 {
			return nil, nil, fmt.Errorf("missing chunk header CRLF")
		}
		header := string(remaining[:idx])
		remaining = remaining[idx+2:]

		// Parse chunk size (before the semicolon)
		sizeStr := header
		if semi := strings.IndexByte(header, ';'); semi >= 0 {
			sizeStr = header[:semi]
		}
		var chunkSize int
		if _, err := fmt.Sscanf(sizeStr, "%x", &chunkSize); err != nil {
			return nil, nil, fmt.Errorf("invalid chunk size %q: %v", sizeStr, err)
		}
		if chunkSize == 0 {
			break // terminal chunk — trailers follow
		}
		if len(remaining) < chunkSize+2 {
			return nil, nil, fmt.Errorf("chunk data truncated")
		}
		result = append(result, remaining[:chunkSize]...)
		remaining = remaining[chunkSize+2:] // skip data + \r\n
	}

	// Parse trailing headers after the terminal chunk.
	// Format: key:value\r\n ... \r\n (empty line ends trailers)
	trailers := make(map[string]string)
	for len(remaining) > 0 {
		idx := bytes.Index(remaining, []byte("\r\n"))
		if idx < 0 || idx == 0 {
			break // empty line or end of data
		}
		line := string(remaining[:idx])
		remaining = remaining[idx+2:]
		if colon := strings.IndexByte(line, ':'); colon > 0 {
			key := strings.TrimSpace(line[:colon])
			val := strings.TrimSpace(line[colon+1:])
			// Skip the trailer signature — it's tied to the original signer
			if strings.ToLower(key) != "x-amz-trailer-signature" {
				trailers[key] = val
			}
		}
	}

	return result, trailers, nil
}

// isCreateBucket detects PUT /bucket-name (no object key, no subresource that
// indicates a different operation like ?acl, ?policy, ?tagging, etc.)
func isCreateBucket(r *http.Request) bool {
	path := strings.TrimPrefix(r.URL.Path, "/")
	path = strings.TrimSuffix(path, "/")
	if path == "" || strings.Contains(path, "/") {
		return false // root or has object key
	}
	// If there's a query string with known subresource params, it's not CreateBucket
	q := r.URL.RawQuery
	if q == "" {
		return true
	}
	// These indicate bucket-level operations, not CreateBucket
	for _, sub := range []string{"acl", "policy", "tagging", "versioning",
		"lifecycle", "cors", "encryption", "logging", "replication",
		"object-lock", "notification", "uploads", "delete"} {
		if strings.Contains(q, sub) {
			return false
		}
	}
	return true
}

// needsLocationConstraint returns true if the body is empty or doesn't
// already contain a LocationConstraint, and the region is not us-east-1
// (which doesn't need one).
func needsLocationConstraint(body []byte, region string) bool {
	if region == "us-east-1" {
		return false
	}
	if len(body) == 0 {
		return true
	}
	return !strings.Contains(string(body), "LocationConstraint")
}

func querySnippet(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	q := r.URL.RawQuery
	if len(q) > 60 {
		q = q[:60] + "..."
	}
	return "?" + q
}

// ---------------------------------------------------------------------------
// S3 error response
// ---------------------------------------------------------------------------

type S3ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestId string   `xml:"RequestId"`
}

func s3Error(w http.ResponseWriter, code, message string, status int) {
	resp := S3ErrorResponse{
		Code:      code,
		Message:   message,
		RequestId: fmt.Sprintf("proxy-%d", time.Now().UnixNano()),
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	enc.Encode(resp)
}
