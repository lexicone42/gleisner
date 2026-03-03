#!/usr/bin/env bash
# deploy/setup-iam.sh — Create the IAM role and instance profile for gleisner EC2 sessions.
#
# Only needs to be run once per AWS account. Creates:
#   - IAM role: gleisner-session-role
#   - Instance profile: gleisner-session-profile
#   - Policy: S3 read/write to the specified bucket
#
# Usage:
#   ./deploy/setup-iam.sh --bucket my-gleisner-bucket [--region us-east-1]

set -euo pipefail

BUCKET=""
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
ROLE_NAME="gleisner-session-role"
PROFILE_NAME="gleisner-session-profile"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --bucket) BUCKET="$2"; shift 2 ;;
        --region) REGION="$2"; shift 2 ;;
        *) echo "unknown: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$BUCKET" ]]; then
    echo "error: --bucket is required" >&2
    exit 1
fi

echo "setup: creating IAM role ${ROLE_NAME} for bucket ${BUCKET}" >&2

# Trust policy: allow EC2 to assume this role
TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ec2.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}'

# Create role (ignore if exists)
aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document "$TRUST_POLICY" \
    --description "Gleisner forge session role - S3 access for package evaluation" \
    2>/dev/null || echo "setup: role ${ROLE_NAME} already exists" >&2

# Inline policy: S3 access to the specific bucket
S3_POLICY=$(cat <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "s3:GetObject",
      "s3:PutObject",
      "s3:ListBucket",
      "s3:DeleteObject"
    ],
    "Resource": [
      "arn:aws:s3:::${BUCKET}",
      "arn:aws:s3:::${BUCKET}/*"
    ]
  }]
}
POLICY
)

aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "gleisner-s3-access" \
    --policy-document "$S3_POLICY"

echo "setup: attached S3 policy for bucket ${BUCKET}" >&2

# Create instance profile (ignore if exists)
aws iam create-instance-profile \
    --instance-profile-name "$PROFILE_NAME" \
    2>/dev/null || echo "setup: profile ${PROFILE_NAME} already exists" >&2

# Add role to profile (ignore if already added)
aws iam add-role-to-instance-profile \
    --instance-profile-name "$PROFILE_NAME" \
    --role-name "$ROLE_NAME" \
    2>/dev/null || echo "setup: role already in profile" >&2

echo "setup: instance profile ${PROFILE_NAME} ready" >&2
echo ""
echo "Add this to your ec2-deploy.sh invocation or set GLEISNER_INSTANCE_PROFILE:"
echo "  export GLEISNER_INSTANCE_PROFILE=${PROFILE_NAME}"
echo ""
echo "Or pass to aws ec2 run-instances:"
echo "  --iam-instance-profile Name=${PROFILE_NAME}"
