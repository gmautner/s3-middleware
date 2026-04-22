#!/usr/bin/env bash
# run-s3tests.sh — Run Ceph s3-tests against the S3 middleware.
#
# Usage: ./run-s3tests.sh [test_dir] [pytest_args...]
#
# Prerequisites:
#   - S3 middleware running (all 3 ports: admin, STS, S3 proxy)
#   - s3tests.conf configured with credentials and [s3 middleware] section
#   - setup-tests.sh already run
#
# Examples:
#   ./run-s3tests.sh                                          # full suite
#   ./run-s3tests.sh ~/s3-middleware-tests -k test_bucket_list_many  # single test
#   ./run-s3tests.sh ~/s3-middleware-tests --tb=short         # with tracebacks

set -euo pipefail

TEST_DIR="${1:-$HOME/s3-middleware-tests}"
shift 2>/dev/null || true

cd "$TEST_DIR/s3-tests"

S3TEST_CONF=s3tests.conf \
AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-sa-east-1}" \
.venv/bin/python -m pytest -v \
    s3tests/functional/test_s3.py \
    -k "not fails_on_aws" \
    --tb=no \
    "$@"
