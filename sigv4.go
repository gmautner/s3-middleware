package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// verifySigV4 verifies the AWS SigV4 signature on a request.
// Returns the access key on success.
func verifySigV4(r *http.Request, body []byte, db *DB) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return "", fmt.Errorf("unsupported auth scheme")
	}
	authHeader = strings.TrimPrefix(authHeader, "AWS4-HMAC-SHA256 ")

	// Parse fields — handle both ", " (AWS SDK) and "," (minio-go) separators
	var parts []string
	if strings.Contains(authHeader, ", ") {
		parts = strings.SplitN(authHeader, ", ", 3)
	} else {
		parts = strings.SplitN(authHeader, ",", 3)
	}
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed Authorization header")
	}

	// Credential
	credPart := strings.TrimPrefix(strings.TrimSpace(parts[0]), "Credential=")
	credParts := strings.Split(credPart, "/")
	if len(credParts) != 5 {
		return "", fmt.Errorf("malformed credential scope")
	}
	accessKey := credParts[0]
	date := credParts[1]
	region := credParts[2]
	service := credParts[3]

	// SignedHeaders
	signedHeadersStr := strings.TrimPrefix(strings.TrimSpace(parts[1]), "SignedHeaders=")
	signedHeaders := strings.Split(signedHeadersStr, ";")

	// Signature
	providedSig := strings.TrimPrefix(strings.TrimSpace(parts[2]), "Signature=")

	// Look up secret key from database
	account, err := db.GetAccountByAccessKey(accessKey)
	if err != nil {
		return "", fmt.Errorf("database error: %w", err)
	}
	if account == nil {
		return "", fmt.Errorf("unknown access key: %s", accessKey)
	}
	secretKey := account.SecretKey

	// Build canonical headers
	var canonicalHeaders strings.Builder
	for _, h := range signedHeaders {
		h = strings.TrimSpace(h)
		var val string
		if h == "host" {
			val = r.Host
		} else {
			vals := r.Header.Values(http.CanonicalHeaderKey(h))
			if len(vals) > 1 {
				val = strings.Join(vals, ",")
			} else {
				val = r.Header.Get(h)
			}
		}
		canonicalHeaders.WriteString(h + ":" + val + "\n")
	}

	// Payload hash
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = sha256Hex(body)
	} else if payloadHash == "UNSIGNED-PAYLOAD" || strings.HasPrefix(payloadHash, "STREAMING-") {
		// Use as-is
	}

	// Canonical request
	canonicalReq := strings.Join([]string{
		r.Method,
		r.URL.EscapedPath(),
		canonicalQueryString(r.URL.RawQuery),
		canonicalHeaders.String(),
		signedHeadersStr,
		payloadHash,
	}, "\n")

	// String to sign
	amzDate := r.Header.Get("X-Amz-Date")
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalReq)),
	}, "\n")

	// Derive signing key and compute signature
	signingKey := deriveSigningKey(secretKey, date, region, service)
	computedSig := fmt.Sprintf("%x", hmacSHA256(signingKey, []byte(stringToSign)))

	if computedSig != providedSig {
		return "", fmt.Errorf("signature mismatch")
	}

	return accessKey, nil
}

func deriveSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

func canonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	params, _ := url.ParseQuery(rawQuery)
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vals := params[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, awsQueryEscape(k)+"="+awsQueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func awsQueryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}
