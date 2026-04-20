package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type stsHandler struct {
	db     *DB
	awsCfg *AWSConfig
	cache  *CredCache
}

func newSTSHandler(db *DB, awsCfg *AWSConfig, cache *CredCache) http.Handler {
	return &stsHandler{db: db, awsCfg: awsCfg, cache: cache}
}

func (h *stsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		stsError(w, "Sender", "InvalidAction", "Only POST supported", 405)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		stsError(w, "Sender", "InvalidRequest", "Failed to read body", 400)
		return
	}
	defer r.Body.Close()

	// Verify SigV4
	accessKey, err := verifySigV4(r, body, h.db)
	if err != nil {
		log.Printf("STS auth failed: %v", err)
		stsError(w, "Sender", "SignatureDoesNotMatch", "Signature verification failed", 403)
		return
	}
	log.Printf("STS auth OK: %s", accessKey)

	// Parse action
	params, _ := url.ParseQuery(string(body))
	action := params.Get("Action")
	if action != "AssumeRole" {
		stsError(w, "Sender", "InvalidAction", fmt.Sprintf("Unsupported action: %s", action), 400)
		return
	}

	// Get account and buckets
	account, err := h.db.GetAccountByAccessKey(accessKey)
	if err != nil || account == nil {
		stsError(w, "Sender", "InvalidRequest", "Account not found", 400)
		return
	}

	buckets, err := h.db.ListBucketsByAccount(account.ID)
	if err != nil {
		stsError(w, "Receiver", "InternalError", "Failed to list buckets", 500)
		return
	}

	// Build session policy
	sessionPolicy := buildSessionPolicy(buckets)

	// Call AWS STS AssumeRole
	stsClient := sts.New(sts.Options{
		Region:      h.awsCfg.Region,
		Credentials: credentials.NewStaticCredentialsProvider(h.awsCfg.AccessKey, h.awsCfg.SecretKey, ""),
	})

	result, err := stsClient.AssumeRole(context.Background(), &sts.AssumeRoleInput{
		RoleArn:         aws.String(h.awsCfg.RoleARN),
		RoleSessionName: aws.String(fmt.Sprintf("s3mw-%s-%d", accessKey[:10], time.Now().Unix())),
		Policy:          aws.String(sessionPolicy),
		DurationSeconds: aws.Int32(3600),
	})
	if err != nil {
		log.Printf("AssumeRole failed: %v", err)
		stsError(w, "Receiver", "InternalError", "AssumeRole failed", 500)
		return
	}

	creds := result.Credentials

	// Build XML response
	resp := AssumeRoleResponse{
		XMLNS: "https://sts.amazonaws.com/doc/2011-06-15/",
		Result: AssumeRoleResult{
			AssumedRoleUser: AssumedRoleUser{
				AssumedRoleId: *result.AssumedRoleUser.AssumedRoleId,
				Arn:           *result.AssumedRoleUser.Arn,
			},
			Credentials: STSCredentials{
				AccessKeyId:     *creds.AccessKeyId,
				SecretAccessKey: *creds.SecretAccessKey,
				SessionToken:    *creds.SessionToken,
				Expiration:      creds.Expiration.Format(time.RFC3339),
			},
		},
		Metadata: ResponseMetadata{
			RequestId: fmt.Sprintf("s3mw-%d", time.Now().UnixNano()),
		},
	}

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	enc.Encode(resp)
}

// buildSessionPolicy creates a session policy scoped to the given buckets.
// Uses the Deny list from the PRD (section 5.6).
func buildSessionPolicy(buckets []string) string {
	var resources []string
	for _, b := range buckets {
		resources = append(resources, fmt.Sprintf(`"arn:aws:s3:::%s"`, b))
		resources = append(resources, fmt.Sprintf(`"arn:aws:s3:::%s/*"`, b))
	}

	resourceStr := "[]"
	if len(resources) > 0 {
		resourceStr = "[" + strings.Join(resources, ", ") + "]"
	}

	return fmt.Sprintf(`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowObjectOperations",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:ListBucketMultipartUploads",
        "s3:ListMultipartUploadParts",
        "s3:AbortMultipartUpload",
        "s3:PutObjectAcl",
        "s3:GetObjectAcl",
        "s3:GetObjectVersion",
        "s3:DeleteObjectVersion",
        "s3:PutObjectTagging",
        "s3:GetObjectTagging",
        "s3:DeleteObjectTagging"
      ],
      "Resource": %s
    },
    {
      "Sid": "DenyBucketAdmin",
      "Effect": "Deny",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutBucketVersioning",
        "s3:PutEncryptionConfiguration",
        "s3:DeleteEncryptionConfiguration",
        "s3:PutBucketPolicy",
        "s3:DeleteBucketPolicy",
        "s3:PutBucketAcl",
        "s3:PutBucketOwnershipControls",
        "s3:PutPublicAccessBlock",
        "s3:DeletePublicAccessBlock",
        "s3:PutObjectLockConfiguration",
        "s3:PutBucketTagging",
        "s3:DeleteBucketTagging"
      ],
      "Resource": "arn:aws:s3:::*"
    }
  ]
}`, resourceStr)
}

// getOrAssumeRole gets cached STS credentials or calls AssumeRole.
// Used by the S3 proxy.
func (h *stsHandler) getOrAssumeRole(accessKey string, accountID string) (aws.Credentials, error) {
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
		RoleSessionName: aws.String(fmt.Sprintf("s3mw-%s-%d", accessKey[:10], time.Now().Unix())),
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

// XML types for STS responses

type AssumeRoleResponse struct {
	XMLName  xml.Name         `xml:"AssumeRoleResponse"`
	XMLNS    string           `xml:"xmlns,attr"`
	Result   AssumeRoleResult `xml:"AssumeRoleResult"`
	Metadata ResponseMetadata `xml:"ResponseMetadata"`
}

type AssumeRoleResult struct {
	AssumedRoleUser AssumedRoleUser `xml:"AssumedRoleUser"`
	Credentials     STSCredentials  `xml:"Credentials"`
}

type AssumedRoleUser struct {
	AssumedRoleId string `xml:"AssumedRoleId"`
	Arn           string `xml:"Arn"`
}

type STSCredentials struct {
	AccessKeyId     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type ErrorResponseXML struct {
	XMLName  xml.Name         `xml:"ErrorResponse"`
	XMLNS    string           `xml:"xmlns,attr"`
	Error    STSErrorXML      `xml:"Error"`
	Metadata ResponseMetadata `xml:"ResponseMetadata"`
}

type STSErrorXML struct {
	Type    string `xml:"Type"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

type ResponseMetadata struct {
	RequestId string `xml:"RequestId"`
}

func stsError(w http.ResponseWriter, errType, code, message string, statusCode int) {
	resp := ErrorResponseXML{
		XMLNS: "https://sts.amazonaws.com/doc/2011-06-15/",
		Error: STSErrorXML{
			Type:    errType,
			Code:    code,
			Message: message,
		},
		Metadata: ResponseMetadata{
			RequestId: fmt.Sprintf("s3mw-err-%d", time.Now().UnixNano()),
		},
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(statusCode)
	w.Write([]byte(xml.Header))
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	enc.Encode(resp)
}
