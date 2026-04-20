package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// verifySigV4 verifies an AWS Signature V4 signed request. If body is
// provided and x-amz-content-sha256 is missing, the body hash is computed.
// Otherwise the header value is used as the payload hash.
func verifySigV4(r *http.Request, body []byte, db *DB) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		return "", fmt.Errorf("unsupported auth scheme")
	}

	remainder := authHeader[len("AWS4-HMAC-SHA256 "):]
	// AWS spec allows ", " or "," between Credential, SignedHeaders, Signature.
	// The AWS SDK uses ", " but minio-go uses ",". Normalize to handle both.
	parts := strings.Split(remainder, ", ")
	if len(parts) != 3 {
		parts = strings.Split(remainder, ",")
	}
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed Authorization header")
	}
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}

	// Credential
	if !strings.HasPrefix(parts[0], "Credential=") {
		return "", fmt.Errorf("missing Credential")
	}
	credParts := strings.Split(strings.TrimPrefix(parts[0], "Credential="), "/")
	if len(credParts) != 5 || credParts[4] != "aws4_request" {
		return "", fmt.Errorf("malformed credential scope")
	}
	accessKey := credParts[0]
	date := credParts[1]
	region := credParts[2]
	service := credParts[3]

	// SignedHeaders
	if !strings.HasPrefix(parts[1], "SignedHeaders=") {
		return "", fmt.Errorf("missing SignedHeaders")
	}
	signedHeadersStr := strings.TrimPrefix(parts[1], "SignedHeaders=")
	signedHeaders := strings.Split(signedHeadersStr, ";")

	// Signature
	if !strings.HasPrefix(parts[2], "Signature=") {
		return "", fmt.Errorf("missing Signature")
	}
	providedSig := strings.TrimPrefix(parts[2], "Signature=")

	// Look up customer — DB instead of hardcoded map
	account, err := db.GetAccountByAccessKey(accessKey)
	if err != nil {
		return "", fmt.Errorf("database error: %w", err)
	}
	if account == nil {
		return "", fmt.Errorf("unknown access key: %s", accessKey)
	}
	secretKey := account.SecretKey

	// Canonical headers — for headers with multiple values (e.g.
	// x-amz-object-attributes sent once per attribute by aws-sdk-go-v2),
	// join all values with "," per the SigV4 spec.
	var canonHeaders strings.Builder
	for _, h := range signedHeaders {
		var val string
		if h == "host" {
			val = r.Host
		} else {
			vals := r.Header.Values(h)
			for i := range vals {
				vals[i] = strings.TrimSpace(vals[i])
			}
			val = strings.Join(vals, ",")
		}
		canonHeaders.WriteString(h)
		canonHeaders.WriteByte(':')
		canonHeaders.WriteString(val)
		canonHeaders.WriteByte('\n')
	}

	// Payload hash: use x-amz-content-sha256 if the client declared it.
	// For UNSIGNED-PAYLOAD or STREAMING-*, the literal string is used.
	// If the header is missing, compute from the buffered body.
	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		payloadHash = sha256Hex(body)
	}

	// Canonical request — use EscapedPath() which returns the encoded path
	// matching what the client signed over. It uses RawPath when valid,
	// or re-encodes Path correctly (handling literal % etc.)
	canonicalRequest := strings.Join([]string{
		r.Method,
		canonicalURIEscaped(r.URL.EscapedPath()),
		canonicalQueryString(r.URL.RawQuery),
		canonHeaders.String(),
		signedHeadersStr,
		payloadHash,
	}, "\n")

	// String to sign
	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return "", fmt.Errorf("missing X-Amz-Date")
	}
	scope := fmt.Sprintf("%s/%s/%s/aws4_request", date, region, service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Verify
	signingKey := deriveSigningKey(secretKey, date, region, service)
	expectedSig := hex.EncodeToString(hmacSHA256(signingKey, []byte(stringToSign)))

	if expectedSig != providedSig {
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
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// canonicalURIEscaped takes the already-escaped path from url.EscapedPath()
// and returns it as-is (it's already in canonical form).
func canonicalURIEscaped(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	return path
}

// awsQueryEscape encodes a string per AWS Sig V4 rules: RFC 3986 with
// space as %20 (not + like url.QueryEscape).
func awsQueryEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
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
		sort.Strings(params[k])
		for _, v := range params[k] {
			parts = append(parts, awsQueryEscape(k)+"="+awsQueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}
