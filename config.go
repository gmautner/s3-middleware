package main

import (
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// AWSConfig holds the service account credentials and settings.
type AWSConfig struct {
	AccessKey string
	SecretKey string
	RoleARN   string
	Region    string
}

// cachedCreds holds temporary STS credentials for an account.
type cachedCreds struct {
	creds      aws.Credentials
	expiration time.Time
}

// CredCache is a thread-safe cache of STS credentials keyed by access key.
type CredCache struct {
	mu      sync.Mutex
	entries map[string]*cachedCreds
}

func (c *CredCache) get(accessKey string) (*cachedCreds, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[accessKey]
	if !ok {
		return nil, false
	}
	// Refresh 5 minutes before expiry
	if time.Now().After(entry.expiration.Add(-5 * time.Minute)) {
		delete(c.entries, accessKey)
		return nil, false
	}
	return entry, true
}

func (c *CredCache) set(accessKey string, creds aws.Credentials, expiration time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[accessKey] = &cachedCreds{
		creds:      creds,
		expiration: expiration,
	}
}

func (c *CredCache) invalidate(accessKey string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, accessKey)
}
