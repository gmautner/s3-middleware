# S3 Middleware

S3-compatible middleware for [Apache CloudStack](https://cloudstack.apache.org/).
Single Go binary that sits between CloudStack and AWS S3, providing
per-tenant bucket isolation through STS AssumeRole with scoped session policies.

## Architecture

```
CloudStack Management Server
  └─ AWSS3ObjectStoreDriverImpl
        │ Admin API (HTTP)
        ▼
  S3 Middleware
    :8090  Admin API    ← CloudStack driver
    :8085  STS endpoint ← tenant credential vending
    :9000  S3 proxy     ← tenant S3 operations
        │
        ├─ Postgres (credentials, bucket-account mappings)
        │
        └─ AWS S3 / STS (service account)
```

Three listener ports, one binary:

| Port | Endpoint | Purpose |
|------|----------|---------|
| 8090 | Admin API | User/bucket management (called by CloudStack) |
| 8085 | STS | AssumeRole with scoped session policies (called by tenants) |
| 9000 | S3 Proxy | Reverse proxy to S3 with re-signed requests (called by tenants) |

## Prerequisites

- **Go 1.21+**
- **Postgres 14+** (any version with `IF NOT EXISTS` support)
- **AWS account** with:
  - An IAM user (service account) with S3 and STS permissions
  - An IAM role for STS AssumeRole (trust policy allows only the service account)

See the [CloudStack plugin README](https://github.com/gmautner/cloudstack/blob/feature/aws-s3-object-storage-provider/plugins/storage/object/s3/README.md)
for detailed AWS setup instructions including IAM policies.

## Building

```bash
go build -o s3-middleware .
```

## Configuration

All configuration is via environment variables.

### Required

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | Postgres connection string (e.g., `postgres://user:pass@host:5432/dbname?sslmode=disable`) |
| `AWS_ACCESS_KEY_ID` | Service account access key |
| `AWS_SECRET_ACCESS_KEY` | Service account secret key |
| `AWS_ROLE_ARN` | IAM role ARN for STS AssumeRole |
| `ADMIN_API_KEY` | Bearer token for admin API authentication |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `AWS_REGION` | `sa-east-1` | Target S3 region |
| `ADMIN_LISTEN` | `:8090` | Admin API listen address |
| `STS_LISTEN` | `:8085` | STS endpoint listen address |
| `S3_LISTEN` | `:9000` | S3 proxy listen address |
| `ADMIN_ALLOWED_IPS` | `127.0.0.1` | Comma-separated IP allowlist for admin API |

## Running

### Postgres

```bash
podman run -d --name s3mw-postgres -p 5432:5432 \
  -e POSTGRES_DB=s3middleware -e POSTGRES_USER=s3mw -e POSTGRES_PASSWORD=s3mw \
  postgres:17
```

The middleware auto-creates its schema on startup.

### Middleware

```bash
export DATABASE_URL="postgres://s3mw:s3mw@localhost:5432/s3middleware?sslmode=disable"
export AWS_ACCESS_KEY_ID="<service account access key>"
export AWS_SECRET_ACCESS_KEY="<service account secret key>"
export AWS_ROLE_ARN="arn:aws:iam::<account-id>:role/<role-name>"
export AWS_REGION="sa-east-1"
export ADMIN_API_KEY="<choose a secret>"
export ADMIN_ALLOWED_IPS="127.0.0.1,::1"

./s3-middleware
```

Verify:

```bash
curl -H "Authorization: Bearer <ADMIN_API_KEY>" http://localhost:8090/admin/health
# {"status":"healthy"}
```

## Bucket Naming Convention

Bucket names **must start with the account name**. This enables
constant-size session policies — the STS policy uses a wildcard ARN
(`arn:aws:s3:::accountname*`) instead of listing each bucket individually,
eliminating the AWS 2048-byte packed policy size limit.

Examples for account `johndoe`:
- `johndoe-docs` — valid
- `johndoe-photos-2024` — valid
- `photos-johndoe` — **rejected**

The middleware enforces this on bucket creation and returns an error
if the name doesn't match:

```json
{"error": "bucket name must start with account name 'johndoe'"}
```

## Admin API Reference

All endpoints require `Authorization: Bearer <ADMIN_API_KEY>` header
and client IP in `ADMIN_ALLOWED_IPS`.

### POST /admin/users

Create an account with auto-generated S3 credentials.

```json
// Request
{"id": "account-uuid", "name": "accountname"}

// Response (201)
{"id": "account-uuid", "name": "accountname",
 "access_key": "AKIACS...", "secret_key": "..."}
```

Returns the existing account (200) if the ID already exists.

### GET /admin/users/{id}

Retrieve account credentials.

```json
// Response (200)
{"id": "account-uuid", "name": "accountname",
 "access_key": "AKIACS...", "secret_key": "..."}
```

### DELETE /admin/users/{id}

Delete account and all its bucket mappings (cascading DB delete).

### POST /admin/buckets

Create a bucket in S3 and record the account mapping.

```json
// Request
{"name": "accountname-mybucket", "account_id": "account-uuid",
 "object_lock": false}

// Response (201)
{"name": "accountname-mybucket", "account_id": "account-uuid",
 "url": "https://s3.sa-east-1.amazonaws.com/accountname-mybucket"}
```

The middleware handles:
1. HeadBucket collision check (S3 bucket names are globally unique)
2. CreateBucket with region LocationConstraint
3. DeletePublicAccessBlock (enables ACLs)
4. PutBucketOwnershipControls (BucketOwnerPreferred)
5. Credential cache invalidation for the account

### DELETE /admin/buckets/{name}

Delete bucket from S3 and remove the mapping. Fails if bucket is not empty.

### PUT /admin/buckets/{name}/encryption

```json
{"enabled": true}   // enable SSE-S3
{"enabled": false}  // remove explicit encryption config
```

### PUT /admin/buckets/{name}/versioning

```json
{"enabled": true}   // enable versioning
{"enabled": false}  // suspend versioning
```

### PUT /admin/buckets/{name}/policy

```json
{"policy": "public"}   // allow anonymous GetObject
{"policy": "private"}  // remove bucket policy
```

### GET /admin/health

Returns `{"status":"healthy"}` if Postgres and AWS are reachable.

## Tenant Access Modes

Tenants access their buckets using credentials generated by the middleware
(returned from `POST /admin/users`). Two modes are supported simultaneously.

### STS Direct

Tenant configures AWS CLI to redirect STS to the middleware. The SDK
obtains temporary AWS credentials via AssumeRole, then talks directly
to S3 (proxy not in data path).

```ini
# ~/.aws/credentials
[source]
aws_access_key_id = <middleware access key>
aws_secret_access_key = <middleware secret key>

# ~/.aws/config
[profile cloudstack]
role_arn = <IAM role ARN>
source_profile = source
region = sa-east-1
services = mw

[services mw]
sts =
  endpoint_url = http://<middleware-host>:8085
```

```bash
aws s3 ls s3://accountname-mybucket --profile cloudstack
```

### S3 Proxy

All S3 operations routed through the proxy. The proxy verifies
SigV4 signatures, obtains scoped STS credentials (cached), re-signs
the request, and forwards to S3.

```bash
export AWS_ACCESS_KEY_ID=<middleware access key>
export AWS_SECRET_ACCESS_KEY=<middleware secret key>
aws s3 ls s3://accountname-mybucket --endpoint-url http://<middleware-host>:9000
```

## Session Policy

The session policy scopes each tenant to buckets prefixed with their
account name and denies all bucket-admin operations:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::accountname*", "arn:aws:s3:::accountname*/*"]
    },
    {
      "Effect": "Deny",
      "Action": ["s3:CreateBucket", "s3:DeleteBucket", "s3:PutBucketVersioning",
                  "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutBucketAcl",
                  "s3:PutBucketOwnershipControls", "s3:PutBucketTagging",
                  "s3:DeleteBucketTagging", "s3:ListAllMyBuckets",
                  "s3:PutEncryptionConfiguration", "s3:DeleteEncryptionConfiguration",
                  "s3:PutPublicAccessBlock", "s3:DeletePublicAccessBlock",
                  "s3:PutObjectLockConfiguration"],
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

The Allow uses `s3:*` because the explicit Deny takes precedence for
bucket-admin operations. The Deny applies to all buckets (`arn:aws:s3:::*`),
ensuring tenants cannot create, delete, or configure buckets — those
operations go through CloudStack via the admin API.

## Database Schema

Two tables, auto-created on startup:

```sql
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,          -- CloudStack account UUID
    name TEXT NOT NULL,           -- CloudStack account name (bucket prefix)
    access_key TEXT UNIQUE NOT NULL,
    secret_key TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE buckets (
    id SERIAL PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,    -- S3 bucket name
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## Horizontal Scalability

Multiple middleware instances can run behind a load balancer. All
instances share the same Postgres database. STS credential caches
are per-instance (in-memory) and populated on demand. No inter-instance
coordination is required.

## Testing

See [tests/README.md](tests/README.md) for S3 compatibility testing
with Ceph s3-tests and MinIO Mint suites.
