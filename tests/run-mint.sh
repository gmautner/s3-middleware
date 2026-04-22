#!/usr/bin/env bash
# run-mint.sh — Run MinIO Mint test suites against the S3 middleware.
#
# Usage: ./run-mint.sh [test_dir]
#
# Prerequisites:
#   - S3 middleware running (all 3 ports: admin, STS, S3 proxy)
#   - setup-tests.sh already run
#
# Environment variables (required):
#   SERVER_ENDPOINT     S3 proxy host:port (e.g., localhost:9090)
#   ACCESS_KEY          Main account access key
#   SECRET_KEY          Main account secret key
#   MIDDLEWARE_ADMIN_URL    Admin API URL (e.g., http://localhost:8090)
#   MIDDLEWARE_API_KEY      Admin API bearer token
#   MIDDLEWARE_ACCOUNT_ID   Main account UUID

set -euo pipefail

TEST_DIR="${1:-$HOME/s3-middleware-tests}"

: "${SERVER_ENDPOINT:?Set SERVER_ENDPOINT (e.g., localhost:9090)}"
: "${ACCESS_KEY:?Set ACCESS_KEY}"
: "${SECRET_KEY:?Set SECRET_KEY}"
: "${MIDDLEWARE_ADMIN_URL:?Set MIDDLEWARE_ADMIN_URL (e.g., http://localhost:8090)}"
: "${MIDDLEWARE_API_KEY:?Set MIDDLEWARE_API_KEY}"
: "${MIDDLEWARE_ACCOUNT_ID:?Set MIDDLEWARE_ACCOUNT_ID}"

export SERVER_ENDPOINT ACCESS_KEY SECRET_KEY ENABLE_HTTPS=0
export MIDDLEWARE_ADMIN_URL MIDDLEWARE_API_KEY MIDDLEWARE_ACCOUNT_ID
export SERVER_REGION="${SERVER_REGION:-sa-east-1}"

PASS=0
FAIL=0

run_suite() {
    local name="$1"
    local binary="$2"
    local extra_env="${3:-}"

    echo ""
    echo "=== $name ==="
    local output
    if output=$(env $extra_env "$binary" 2>&1); then
        : # suite ran
    fi

    local p f
    p=$(echo "$output" | grep -c '"status":"PASS"' || true)
    f=$(echo "$output" | grep -c '"status":"FAIL"' || true)
    PASS=$((PASS + p))
    FAIL=$((FAIL + f))
    echo "$name: $p passed, $f failed"

    if [ "$f" -gt 0 ]; then
        echo "Failures:"
        echo "$output" | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        d=json.loads(line.strip())
        if d.get('status')=='FAIL':
            print(f'  {d.get(\"function\",\"\")}: {(d.get(\"error\",\"\") or d.get(\"message\",\"\"))[:100]}')
    except: pass
" 2>/dev/null || true
    fi
}

# aws-sdk-go-v2
run_suite "aws-sdk-go-v2" "$TEST_DIR/mint/run/core/aws-sdk-go-v2/aws-sdk-go-v2"

# versioning
run_suite "versioning" "$TEST_DIR/mint/build/versioning/versioning-tests"

# minio-go (needs background DB cleanup to prevent policy overflow)
echo ""
echo "=== minio-go ==="
# Start background cleaner
(while true; do
    podman exec s3mw-postgres psql -U s3mw -d s3middleware -q -c \
        "DELETE FROM buckets WHERE name LIKE 'minio-go-test-%' AND created_at < NOW() - INTERVAL '5 seconds';" \
        2>/dev/null || true
    sleep 1.5
done) &
CLEANER_PID=$!

output=$(env MINT_MODE=full RUN_ON_FAIL=1 "$TEST_DIR/mint/run/core/minio-go/minio-go" 2>&1 || true)
kill $CLEANER_PID 2>/dev/null || true
wait $CLEANER_PID 2>/dev/null || true

p=$(echo "$output" | grep -c '"status":"PASS"' || true)
f=$(echo "$output" | grep -c '"status":"FAIL"' || true)
PASS=$((PASS + p))
FAIL=$((FAIL + f))
echo "minio-go: $p passed, $f failed"

# Clean up stale minio-go buckets
podman exec s3mw-postgres psql -U s3mw -d s3middleware -q -c \
    "DELETE FROM buckets WHERE name LIKE 'minio-go-test-%';" 2>/dev/null || true

echo ""
echo "=== TOTAL: $PASS passed, $FAIL failed ==="
