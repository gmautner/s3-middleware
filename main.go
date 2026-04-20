package main

import (
	"log"
	"net/http"
	"os"
	"sync"
)

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

func main() {
	// Required config
	databaseURL := mustEnv("DATABASE_URL")
	awsAccessKey := mustEnv("AWS_ACCESS_KEY_ID")
	awsSecretKey := mustEnv("AWS_SECRET_ACCESS_KEY")
	roleARN := mustEnv("AWS_ROLE_ARN")
	adminAPIKey := mustEnv("ADMIN_API_KEY")

	// Optional config
	region := envOrDefault("AWS_REGION", "sa-east-1")
	adminListen := envOrDefault("ADMIN_LISTEN", ":8090")
	stsListen := envOrDefault("STS_LISTEN", ":8085")
	s3Listen := envOrDefault("S3_LISTEN", ":9000")
	adminAllowedIPs := envOrDefault("ADMIN_ALLOWED_IPS", "127.0.0.1")

	// Initialize database
	db, err := initDB(databaseURL)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// AWS config for the service account
	awsCfg := &AWSConfig{
		AccessKey: awsAccessKey,
		SecretKey: awsSecretKey,
		RoleARN:   roleARN,
		Region:    region,
	}

	// Credential cache for STS sessions
	cache := &CredCache{
		entries: make(map[string]*cachedCreds),
	}

	var wg sync.WaitGroup

	// Admin API server
	wg.Add(1)
	go func() {
		defer wg.Done()
		adminHandler := newAdminHandler(db, awsCfg, adminAPIKey, adminAllowedIPs)
		log.Printf("Admin API listening on %s", adminListen)
		if err := http.ListenAndServe(adminListen, adminHandler); err != nil {
			log.Fatalf("Admin server error: %v", err)
		}
	}()

	// STS endpoint server
	wg.Add(1)
	go func() {
		defer wg.Done()
		stsHandler := newSTSHandler(db, awsCfg, cache)
		log.Printf("STS endpoint listening on %s", stsListen)
		if err := http.ListenAndServe(stsListen, stsHandler); err != nil {
			log.Fatalf("STS server error: %v", err)
		}
	}()

	// S3 proxy endpoint server
	wg.Add(1)
	go func() {
		defer wg.Done()
		s3Handler := newS3ProxyHandler(db, awsCfg, cache)
		log.Printf("S3 proxy endpoint listening on %s", s3Listen)
		if err := http.ListenAndServe(s3Listen, s3Handler); err != nil {
			log.Fatalf("S3 proxy server error: %v", err)
		}
	}()

	log.Printf("S3 Middleware started")
	log.Printf("  Region:    %s", region)
	log.Printf("  Role ARN:  %s", roleARN)
	wg.Wait()
}
