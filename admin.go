package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type adminHandler struct {
	db         *DB
	awsCfg     *AWSConfig
	apiKey     string
	allowedIPs map[string]bool
	mux        *http.ServeMux
}

func newAdminHandler(db *DB, awsCfg *AWSConfig, apiKey, allowedIPs string) http.Handler {
	h := &adminHandler{
		db:         db,
		awsCfg:     awsCfg,
		apiKey:     apiKey,
		allowedIPs: parseAllowedIPs(allowedIPs),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/users", h.handleUsers)
	mux.HandleFunc("/admin/users/", h.handleUser)
	mux.HandleFunc("/admin/buckets", h.handleBuckets)
	mux.HandleFunc("/admin/buckets/", h.handleBucket)
	mux.HandleFunc("/admin/health", h.handleHealth)
	h.mux = mux
	return h
}

func parseAllowedIPs(s string) map[string]bool {
	m := make(map[string]bool)
	for _, ip := range strings.Split(s, ",") {
		ip = strings.TrimSpace(ip)
		if ip != "" {
			m[ip] = true
		}
	}
	return m
}

func (h *adminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// IP allowlist check
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	if !h.allowedIPs[clientIP] {
		jsonError(w, "forbidden: IP not allowed", http.StatusForbidden)
		return
	}

	// API key check
	auth := r.Header.Get("Authorization")
	if auth != "Bearer "+h.apiKey {
		jsonError(w, "unauthorized: invalid API key", http.StatusUnauthorized)
		return
	}

	h.mux.ServeHTTP(w, r)
}

func (h *adminHandler) s3Client() *s3.Client {
	return s3.New(s3.Options{
		Region:      h.awsCfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(h.awsCfg.AccessKey, h.awsCfg.SecretKey, ""),
	})
}

// POST /admin/users — create account with generated credentials
func (h *adminHandler) handleUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		jsonError(w, "invalid request: id is required", http.StatusBadRequest)
		return
	}

	// Check if account already exists
	existing, err := h.db.GetAccount(req.ID)
	if err != nil {
		jsonError(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if existing != nil {
		jsonResp(w, http.StatusOK, existing)
		return
	}

	// Generate synthetic credentials
	accessKey := generateAccessKey()
	secretKey := generateSecretKey()

	if err := h.db.CreateAccount(req.ID, accessKey, secretKey); err != nil {
		jsonError(w, "failed to create account: "+err.Error(), http.StatusInternalServerError)
		return
	}

	jsonResp(w, http.StatusCreated, &Account{
		ID:        req.ID,
		AccessKey: accessKey,
		SecretKey: secretKey,
	})
}

// GET/DELETE /admin/users/{id}
func (h *adminHandler) handleUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	if id == "" {
		jsonError(w, "user id required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		account, err := h.db.GetAccount(id)
		if err != nil {
			jsonError(w, "database error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if account == nil {
			jsonError(w, "account not found", http.StatusNotFound)
			return
		}
		jsonResp(w, http.StatusOK, account)

	case http.MethodDelete:
		if err := h.db.DeleteAccount(id); err != nil {
			jsonError(w, err.Error(), http.StatusNotFound)
			return
		}
		jsonResp(w, http.StatusOK, map[string]string{"status": "deleted"})

	default:
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// POST /admin/buckets — create bucket in S3 + record in DB
func (h *adminHandler) handleBuckets(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Name       string `json:"name"`
		AccountID  string `json:"account_id"`
		ObjectLock bool   `json:"object_lock"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.AccountID == "" {
		jsonError(w, "invalid request: name and account_id are required", http.StatusBadRequest)
		return
	}

	// Verify account exists
	account, err := h.db.GetAccount(req.AccountID)
	if err != nil {
		jsonError(w, "database error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if account == nil {
		jsonError(w, "account not found: "+req.AccountID, http.StatusNotFound)
		return
	}

	client := h.s3Client()
	ctx := context.Background()

	// Check if bucket name is already taken
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(req.Name)})
	if err == nil {
		// Bucket exists — check if we track it
		ownerID, _ := h.db.GetBucketAccount(req.Name)
		if ownerID != "" {
			jsonError(w, fmt.Sprintf("bucket '%s' already exists and is managed by account %s", req.Name, ownerID), http.StatusConflict)
		} else {
			jsonError(w, fmt.Sprintf("bucket '%s' exists in the upstream store but is not managed by this middleware", req.Name), http.StatusConflict)
		}
		return
	}
	// Only proceed if the error is 404 (not found)
	if !isNotFoundError(err) {
		jsonError(w, fmt.Sprintf("bucket name '%s' is already taken in AWS S3", req.Name), http.StatusConflict)
		return
	}

	// Create bucket
	createInput := &s3.CreateBucketInput{
		Bucket: aws.String(req.Name),
	}
	if h.awsCfg.Region != "us-east-1" {
		createInput.CreateBucketConfiguration = &s3types.CreateBucketConfiguration{
			LocationConstraint: s3types.BucketLocationConstraint(h.awsCfg.Region),
		}
	}
	if req.ObjectLock {
		createInput.ObjectLockEnabledForBucket = aws.Bool(true)
	}

	if _, err := client.CreateBucket(ctx, createInput); err != nil {
		jsonError(w, "failed to create bucket: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Post-creation fixups
	// 1. Delete Block Public Access
	_, err = client.DeletePublicAccessBlock(ctx, &s3.DeletePublicAccessBlockInput{
		Bucket: aws.String(req.Name),
	})
	if err != nil {
		log.Printf("[fixup] warning: failed to delete public access block for %s: %v", req.Name, err)
	}

	// 2. Set BucketOwnerPreferred ownership controls
	_, err = client.PutBucketOwnershipControls(ctx, &s3.PutBucketOwnershipControlsInput{
		Bucket: aws.String(req.Name),
		OwnershipControls: &s3types.OwnershipControls{
			Rules: []s3types.OwnershipControlsRule{
				{ObjectOwnership: s3types.ObjectOwnershipBucketOwnerPreferred},
			},
		},
	})
	if err != nil {
		log.Printf("[fixup] warning: failed to set ownership controls for %s: %v", req.Name, err)
	}

	// Record in DB
	if err := h.db.CreateBucket(req.Name, req.AccountID); err != nil {
		// Bucket was created in S3 but DB insert failed — try to clean up
		log.Printf("ERROR: bucket %s created in S3 but DB insert failed: %v", req.Name, err)
		client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(req.Name)})
		jsonError(w, "failed to record bucket: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("Created bucket %s for account %s", req.Name, req.AccountID)
	jsonResp(w, http.StatusCreated, map[string]string{
		"name":       req.Name,
		"account_id": req.AccountID,
		"url":        fmt.Sprintf("https://s3.%s.amazonaws.com/%s", h.awsCfg.Region, req.Name),
	})
}

// DELETE /admin/buckets/{name}, PUT /admin/buckets/{name}/{action}
func (h *adminHandler) handleBucket(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/admin/buckets/")
	parts := strings.SplitN(path, "/", 2)
	bucketName := parts[0]
	if bucketName == "" {
		jsonError(w, "bucket name required", http.StatusBadRequest)
		return
	}

	client := h.s3Client()
	ctx := context.Background()

	// Sub-resource actions: /admin/buckets/{name}/{action}
	if len(parts) == 2 {
		if r.Method != http.MethodPut {
			jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		action := parts[1]
		switch action {
		case "encryption":
			h.handleBucketEncryption(w, r, client, ctx, bucketName)
		case "versioning":
			h.handleBucketVersioning(w, r, client, ctx, bucketName)
		case "policy":
			h.handleBucketPolicy(w, r, client, ctx, bucketName)
		default:
			jsonError(w, "unknown action: "+action, http.StatusBadRequest)
		}
		return
	}

	// DELETE /admin/buckets/{name}
	if r.Method != http.MethodDelete {
		jsonError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if _, err := client.DeleteBucket(ctx, &s3.DeleteBucketInput{Bucket: aws.String(bucketName)}); err != nil {
		if isBucketNotEmpty(err) {
			jsonError(w, fmt.Sprintf("cannot delete bucket '%s': bucket is not empty", bucketName), http.StatusConflict)
			return
		}
		jsonError(w, "failed to delete bucket: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := h.db.DeleteBucket(bucketName); err != nil {
		log.Printf("WARNING: bucket %s deleted from S3 but DB removal failed: %v", bucketName, err)
	}

	log.Printf("Deleted bucket %s", bucketName)
	jsonResp(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *adminHandler) handleBucketEncryption(w http.ResponseWriter, r *http.Request, client *s3.Client, ctx context.Context, bucket string) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Enabled {
		_, err := client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
			Bucket: aws.String(bucket),
			ServerSideEncryptionConfiguration: &s3types.ServerSideEncryptionConfiguration{
				Rules: []s3types.ServerSideEncryptionRule{
					{
						ApplyServerSideEncryptionByDefault: &s3types.ServerSideEncryptionByDefault{
							SSEAlgorithm: s3types.ServerSideEncryptionAes256,
						},
					},
				},
			},
		})
		if err != nil {
			jsonError(w, "failed to set encryption: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		_, err := client.DeleteBucketEncryption(ctx, &s3.DeleteBucketEncryptionInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			jsonError(w, "failed to delete encryption: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *adminHandler) handleBucketVersioning(w http.ResponseWriter, r *http.Request, client *s3.Client, ctx context.Context, bucket string) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	status := s3types.BucketVersioningStatusSuspended
	if req.Enabled {
		status = s3types.BucketVersioningStatusEnabled
	}

	_, err := client.PutBucketVersioning(ctx, &s3.PutBucketVersioningInput{
		Bucket: aws.String(bucket),
		VersioningConfiguration: &s3types.VersioningConfiguration{
			Status: status,
		},
	})
	if err != nil {
		jsonError(w, "failed to set versioning: "+err.Error(), http.StatusInternalServerError)
		return
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *adminHandler) handleBucketPolicy(w http.ResponseWriter, r *http.Request, client *s3.Client, ctx context.Context, bucket string) {
	var req struct {
		Policy string `json:"policy"` // "public" or "private"
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Policy == "public" {
		publicPolicy := fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
      "Resource": "arn:aws:s3:::%s"
    },
    {
      "Sid": "PublicReadGetObject2",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::%s/*"
    }
  ]
}`, bucket, bucket)
		_, err := client.PutBucketPolicy(ctx, &s3.PutBucketPolicyInput{
			Bucket: aws.String(bucket),
			Policy: aws.String(publicPolicy),
		})
		if err != nil {
			jsonError(w, "failed to set policy: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		_, err := client.DeleteBucketPolicy(ctx, &s3.DeleteBucketPolicyInput{
			Bucket: aws.String(bucket),
		})
		if err != nil {
			jsonError(w, "failed to delete policy: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *adminHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Check DB
	if err := h.db.Ping(); err != nil {
		jsonError(w, "database unhealthy: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	// Check AWS connectivity
	client := h.s3Client()
	_, err := client.ListBuckets(context.Background(), &s3.ListBucketsInput{})
	if err != nil {
		jsonError(w, "AWS unhealthy: "+err.Error(), http.StatusServiceUnavailable)
		return
	}

	jsonResp(w, http.StatusOK, map[string]string{"status": "healthy"})
}

// Helpers

func generateAccessKey() string {
	b := make([]byte, 10)
	rand.Read(b)
	return "AKIACS" + fmt.Sprintf("%X", b)[:14]
}

func generateSecretKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b)
}

func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "StatusCode: 404") ||
		strings.Contains(err.Error(), "NotFound") ||
		strings.Contains(err.Error(), "NoSuchBucket")
}

func isBucketNotEmpty(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "BucketNotEmpty")
}

func jsonResp(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, status int) {
	jsonResp(w, status, map[string]string{"error": msg})
}
