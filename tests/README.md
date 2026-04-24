# S3 Middleware — Compatibility Tests

S3 compatibility test suites adapted for the S3 middleware's architecture,
where bucket lifecycle (create, delete, versioning, encryption) is managed
exclusively through the admin API, not the S3 proxy.

## Test Suites

### Ceph s3-tests

453 object-operation tests from the [Ceph s3-tests](https://github.com/ceph/s3-tests)
suite. Two patches are applied:

1. **s3tests-harness-fix.patch** — BypassGovernanceRetention fallback for
   S3 implementations without Object Lock support.
2. **s3tests-middleware.patch** — Redirects bucket create/delete through
   the middleware admin API. Adds an optional `[s3 middleware]` config
   section. When absent, tests run against the S3 proxy directly (POC mode).

### MinIO Mint

Three suites from [MinIO Mint](https://github.com/minio/mint):

| Suite | Tests | Description |
|-------|-------|-------------|
| aws-sdk-go-v2 | ~21 | Basic CRUD, checksums, presigned URLs, multipart |
| versioning | ~12 | PUT/GET/DELETE/LIST with versioning enabled |
| minio-go | ~73 | Comprehensive S3 operations via MinIO Go client |

A Go middleware adapter (`middleware_adapter_awssdk.go`) wraps
`CreateBucket`, `DeleteBucket`, and `PutBucketVersioning` calls to use
the admin API when `MIDDLEWARE_*` environment variables are set.

## Prerequisites

- Go 1.21+
- Python 3.9+ with venv
- Postgres (for middleware DB)
- Podman (for background DB cleanup in minio-go suite)
- S3 middleware running with all 3 ports (admin, STS, S3 proxy)
- At least 3 accounts registered in the middleware

## Quick Start

```bash
# 1. Set up test repos (clone, patch, build)
./setup-tests.sh

# 2. Edit the s3-tests config with your credentials
vi ~/s3-middleware-tests/s3-tests/s3tests.conf

# 3. Run Ceph s3-tests
./run-s3tests.sh

# 4. Run Mint suites
export SERVER_ENDPOINT=localhost:9090
export ACCESS_KEY=<main account access key>
export SECRET_KEY=<main account secret key>
export MIDDLEWARE_ADMIN_URL=http://localhost:8090
export MIDDLEWARE_API_KEY=<admin API key>
export MIDDLEWARE_ACCOUNT_ID=<main account UUID>
./run-mint.sh
```

## Understanding Results

### Expected failure categories

Tests that fail due to the middleware's security architecture are
expected and do not indicate bugs:

| Category | Reason |
|----------|--------|
| Bucket admin (CreateBucket, DeleteBucket) | Tests call S3 API directly; session policy denies |
| Versioning config (PutBucketVersioning) | Managed through CloudStack only |
| Object Lock config | Bucket must be created with lock via CloudStack |
| Encryption config (PutEncryptionConfiguration) | Managed through CloudStack |
| Bucket policy/ACL (PutBucketPolicy, PutBucketAcl) | Managed through CloudStack |
| Bucket tagging (PutBucketTagging) | Denied by session policy |
| ListAllMyBuckets | Denied; bucket listing is a CloudStack feature |
| SigV2 authentication | Proxy only supports SigV4 |
| POST form uploads | Architectural limitation (cannot re-sign) |
| Anonymous access | Proxy requires SigV4 on every request |

### Baseline results

**Ceph s3-tests** (excluding `fails_on_aws`):
- 220 passed, 375 failed, 5 skipped
- 0 content-operation regressions vs POC (all failures are architectural)

**Mint:**
- aws-sdk-go-v2: 20/20 passed
- versioning: 12/12 passed
- minio-go: 39/94 unique tests passed (failures are all architectural)

## Updating Test Suites

To pull the latest upstream changes and re-apply patches:

```bash
cd ~/s3-middleware-tests/s3-tests
git checkout -- .
git pull
# Re-apply patches (may need manual conflict resolution)
git apply /path/to/s3-middleware/tests/s3tests-harness-fix.patch
git apply /path/to/s3-middleware/tests/s3tests-middleware.patch
```

For Mint, re-run `setup-tests.sh` — it resets and rebuilds all suites.

## Bucket Naming for Tests

The middleware requires bucket names to start with the account name
(see [main README](../README.md#bucket-naming-convention)). Test suites
use their own prefixes (e.g., `s3proxy-mint-`, `minio-go-test-`), so
the test account name must be compatible. The setup script and middleware
adapter handle this by creating buckets via the admin API, which
validates the prefix.

## Files

```
tests/
  README.md                          This file
  setup-tests.sh                     One-time setup (clone, patch, build)
  run-s3tests.sh                     Run Ceph s3-tests
  run-mint.sh                        Run all Mint suites
  s3tests-harness-fix.patch          BypassGovernanceRetention fallback
  s3tests-middleware.patch           Middleware admin API bucket redirect
  s3tests.conf.example               Config template for Ceph s3-tests
  mint/
    middleware_adapter_awssdk.go      Go adapter for AWS SDK suites
```
