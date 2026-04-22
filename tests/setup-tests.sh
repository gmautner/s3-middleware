#!/usr/bin/env bash
# setup-tests.sh — Clone and patch test suites for S3 middleware testing.
#
# Usage: ./setup-tests.sh [test_dir]
#   test_dir: directory to clone test repos into (default: ~/s3-middleware-tests)
#
# This script is idempotent — re-running it resets and re-patches the repos.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_DIR="${1:-$HOME/s3-middleware-tests}"

mkdir -p "$TEST_DIR"

echo "=== Setting up test suites in $TEST_DIR ==="

# --- Ceph s3-tests ---
echo ""
echo "--- Ceph s3-tests ---"
if [ ! -d "$TEST_DIR/s3-tests" ]; then
    git clone https://github.com/ceph/s3-tests.git "$TEST_DIR/s3-tests"
else
    echo "s3-tests already cloned, resetting..."
    cd "$TEST_DIR/s3-tests"
    git checkout -- .
    git clean -fd -e .venv -e s3tests.conf
fi

cd "$TEST_DIR/s3-tests"

# Create virtualenv if needed
if [ ! -d .venv ]; then
    python3 -m venv .venv
    .venv/bin/pip install -q -r requirements.txt -e .
fi

# Apply patches
git apply "$SCRIPT_DIR/s3tests-harness-fix.patch"
git apply "$SCRIPT_DIR/s3tests-middleware.patch"
echo "s3-tests patched."

# Copy config template if no config exists
if [ ! -f s3tests.conf ]; then
    cp "$SCRIPT_DIR/s3tests.conf.example" s3tests.conf
    echo "Copied s3tests.conf.example -> s3tests.conf (edit with your credentials)"
fi

# --- MinIO Mint ---
echo ""
echo "--- MinIO Mint ---"
if [ ! -d "$TEST_DIR/mint" ]; then
    git clone https://github.com/minio/mint.git "$TEST_DIR/mint"
else
    echo "mint already cloned"
fi

cd "$TEST_DIR/mint"

# Build aws-sdk-go-v2 suite
echo "Building aws-sdk-go-v2 suite..."
cd run/core/aws-sdk-go-v2
# Copy adapter
cp "$SCRIPT_DIR/mint/middleware_adapter_awssdk.go" middleware_adapter.go
# Replace S3 API calls with middleware wrappers
sed -i.bak 's/s3Client\.CreateBucket(ctx, /mwCreateBucket(ctx, s3Client, /g' main.go
sed -i '' 's/s3Client\.DeleteBucket(ctx, /mwDeleteBucket(ctx, s3Client, /g' main.go
# Comment out tests that don't work with middleware or AWS
sed -i '' 's/^\(\t*\)testSelectObject(ctx, s3Client)/\1\/\/ testSelectObject(ctx, s3Client) \/\/ S3 Select not available/' main.go
sed -i '' 's/^\(\t*\)testCreateBucketError(ctx, s3Client/\1\/\/ testCreateBucketError(ctx, s3Client/' main.go
go build -o aws-sdk-go-v2 .
echo "aws-sdk-go-v2 built."

# Build versioning suite
echo "Building versioning suite..."
cd "$TEST_DIR/mint/build/versioning"
cp "$SCRIPT_DIR/mint/middleware_adapter_awssdk.go" middleware_adapter.go
for f in *.go; do
    [ "$f" = "middleware_adapter.go" ] && continue
    sed -i.bak "s/s3Client\.CreateBucket(ctx, /mwCreateBucket(ctx, s3Client, /g" "$f"
    sed -i '' "s/s3Client\.DeleteBucket(ctx, /mwDeleteBucket(ctx, s3Client, /g" "$f"
    sed -i '' "s/s3Client\.PutBucketVersioning(ctx, /mwPutBucketVersioning(ctx, s3Client, /g" "$f"
done
# Comment out excluded tests (same as POC)
sed -i '' 's/^\(\t*\)testMakeBucket()/\1\/\/ testMakeBucket() \/\/ bucket admin/' main.go
sed -i '' 's/^\(\t*\)testLockingLegalhold()/\1\/\/ testLockingLegalhold() \/\/ requires fake IAM creds/' main.go
sed -i '' 's/^\(\t*\)testPutGetRetentionCompliance()/\1\/\/ testPutGetRetentionCompliance()/' main.go
sed -i '' 's/^\(\t*\)testPutGetDeleteRetentionGovernance()/\1\/\/ testPutGetDeleteRetentionGovernance()/' main.go
sed -i '' 's/^\(\t*\)testLockingRetentionGovernance()/\1\/\/ testLockingRetentionGovernance()/' main.go
sed -i '' 's/^\(\t*\)testLockingRetentionCompliance()/\1\/\/ testLockingRetentionCompliance()/' main.go
go build -o versioning-tests .
echo "versioning built."

# Build minio-go suite
echo "Building minio-go suite..."
cd "$TEST_DIR/mint"
MINT_RUN_CORE_DIR="$TEST_DIR/mint/run/core" "$TEST_DIR/mint/build/minio-go/install.sh"

cd "$TEST_DIR/mint/run/core/minio-go"
# Inject middleware adapter (inline, since build uses single-file compilation)
# Add imports
sed -i '' 's/"bytes"/"bytes"\n\t"encoding\/json"/' main.go

# Add adapter functions after import block
IMPORT_END=$(grep -n "^)" main.go | head -1 | cut -d: -f1)
cat > /tmp/mw_inject.go << 'INJECT'

// Middleware adapter
var (
	middlewareAdminURL  = os.Getenv("MIDDLEWARE_ADMIN_URL")
	middlewareAPIKey    = os.Getenv("MIDDLEWARE_API_KEY")
	middlewareAccountID = os.Getenv("MIDDLEWARE_ACCOUNT_ID")
	middlewareEnabled   = middlewareAdminURL != "" && middlewareAPIKey != "" && middlewareAccountID != ""
)
func createBucketViaAdmin(bucket string) error {
	body, _ := json.Marshal(map[string]interface{}{"name": bucket, "account_id": middlewareAccountID})
	req, _ := http.NewRequest("POST", middlewareAdminURL+"/admin/buckets", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+middlewareAPIKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return fmt.Errorf("admin API: %w", err) }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 { msg, _ := io.ReadAll(resp.Body); return fmt.Errorf("admin API create %s (%d): %s", bucket, resp.StatusCode, msg) }
	return nil
}
func deleteBucketViaAdmin(bucket string) error {
	req, _ := http.NewRequest("DELETE", middlewareAdminURL+"/admin/buckets/"+bucket, nil)
	req.Header.Set("Authorization", "Bearer "+middlewareAPIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	return nil
}
func mwMakeBucket(c *minio.Client, ctx context.Context, bucket string, opts minio.MakeBucketOptions) error {
	if middlewareEnabled { return createBucketViaAdmin(bucket) }
	return c.MakeBucket(ctx, bucket, opts)
}
func mwRemoveBucket(c *minio.Client, ctx context.Context, bucket string) error {
	if middlewareEnabled { return deleteBucketViaAdmin(bucket) }
	return c.RemoveBucket(ctx, bucket)
}
INJECT
sed -i '' "${IMPORT_END}r /tmp/mw_inject.go" main.go

# Replace API calls
sed -i '' 's/c\.MakeBucket(context\.Background(), /mwMakeBucket(c, context.Background(), /g' main.go
sed -i '' 's/c\.RemoveBucket(context\.Background(), /mwRemoveBucket(c, context.Background(), /g' main.go

# Fix Core-typed variable calls (minio.Core has .Client field)
grep -n "minio\.Core{Client:" main.go | grep "c :=" | cut -d: -f1 | while read ln; do
    # Find the next mwMakeBucket(c, call after this line and fix it
    next_make=$(awk -v start="$ln" 'NR>start && /mwMakeBucket\(c,/{print NR; exit}' main.go)
    if [ -n "$next_make" ]; then
        sed -i '' "${next_make}s/mwMakeBucket(c,/mwMakeBucket(c.Client,/" main.go
    fi
done

CGO_ENABLED=0 go build --ldflags "-s -w" -o minio-go main.go
echo "minio-go built."

echo ""
echo "=== Setup complete ==="
echo "Edit $TEST_DIR/s3-tests/s3tests.conf with your credentials, then run:"
echo "  $SCRIPT_DIR/run-s3tests.sh [$TEST_DIR]"
echo "  $SCRIPT_DIR/run-mint.sh [$TEST_DIR]"
