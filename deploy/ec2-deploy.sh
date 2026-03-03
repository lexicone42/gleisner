#!/usr/bin/env bash
# deploy/ec2-deploy.sh — Launch a gleisner forge session on EC2.
#
# This script:
# 1. Builds gleisner release binary (if not already built)
# 2. Uploads binary + minimal.dev package tree + stdlib to S3
# 3. Launches a Fedora 42 (kernel 6.18, Landlock V7) EC2 instance with user-data
# 4. Waits for the session to complete
# 5. Downloads the session manifest and forge output from S3
#
# Prerequisites:
#   - AWS CLI configured (aws sts get-caller-identity works)
#   - An S3 bucket (set GLEISNER_BUCKET or pass --bucket)
#   - An SSH key pair registered in EC2 (optional, for debugging)
#
# Usage:
#   ./deploy/ec2-deploy.sh \
#     --bucket my-gleisner-bucket \
#     --region us-east-1 \
#     --pkgs-dir /path/to/minimal-pkgs \
#     --stdlib-dir /path/to/minimal-std \
#     --packages claude-code,git,ripgrep \
#     --profile konishi
#
# The script prints the session manifest to stdout on success.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────
BUCKET="${GLEISNER_BUCKET:-}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
INSTANCE_TYPE="${GLEISNER_INSTANCE_TYPE:-c6a.xlarge}"
PKGS_DIR=""
STDLIB_DIR=""
PACKAGES=""
PROFILE="konishi"
KEY_NAME="${GLEISNER_SSH_KEY:-}"
PROJECT_DIR="${PWD}"
GLEISNER_BIN=""
CLEANUP="true"

# ── Parse args ────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bucket)       BUCKET="$2"; shift 2 ;;
        --region)       REGION="$2"; shift 2 ;;
        --instance-type) INSTANCE_TYPE="$2"; shift 2 ;;
        --pkgs-dir)     PKGS_DIR="$2"; shift 2 ;;
        --stdlib-dir)   STDLIB_DIR="$2"; shift 2 ;;
        --packages)     PACKAGES="$2"; shift 2 ;;
        --profile)      PROFILE="$2"; shift 2 ;;
        --key-name)     KEY_NAME="$2"; shift 2 ;;
        --project-dir)  PROJECT_DIR="$2"; shift 2 ;;
        --gleisner-bin) GLEISNER_BIN="$2"; shift 2 ;;
        --no-cleanup)   CLEANUP="false"; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# //' | sed 's/^#//'
            exit 0
            ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

# ── Validate ──────────────────────────────────────────────────────────
if [[ -z "$BUCKET" ]]; then
    echo "error: --bucket or GLEISNER_BUCKET is required" >&2
    exit 1
fi
if [[ -z "$PKGS_DIR" ]]; then
    echo "error: --pkgs-dir is required (path to minimal-pkgs)" >&2
    exit 1
fi
if [[ -z "$STDLIB_DIR" ]]; then
    echo "error: --stdlib-dir is required (path to minimal-std)" >&2
    exit 1
fi

# Verify AWS credentials
if ! aws sts get-caller-identity --region "$REGION" >/dev/null 2>&1; then
    echo "error: AWS credentials not configured (aws sts get-caller-identity failed)" >&2
    exit 1
fi

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
SESSION_ID="gleisner-$(date +%Y%m%d-%H%M%S)-$$"
S3_PREFIX="s3://${BUCKET}/sessions/${SESSION_ID}"

echo "deploy: session=${SESSION_ID} bucket=${BUCKET} region=${REGION}" >&2
echo "deploy: instance_type=${INSTANCE_TYPE} profile=${PROFILE}" >&2

# ── Step 1: Build gleisner ────────────────────────────────────────────
if [[ -z "$GLEISNER_BIN" ]]; then
    REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
    GLEISNER_BIN="${REPO_ROOT}/target/release/gleisner"

    if [[ ! -f "$GLEISNER_BIN" ]]; then
        echo "deploy: building gleisner release binary..." >&2
        cargo build --release -p gleisner-cli --manifest-path "${REPO_ROOT}/Cargo.toml"
    fi
fi

if [[ ! -f "$GLEISNER_BIN" ]]; then
    echo "error: gleisner binary not found at ${GLEISNER_BIN}" >&2
    exit 1
fi

echo "deploy: binary=$(file -b "$GLEISNER_BIN" | head -c 60)" >&2

# ── Step 2: Upload to S3 ─────────────────────────────────────────────
echo "deploy: uploading gleisner binary to ${S3_PREFIX}/bin/gleisner" >&2
aws s3 cp "$GLEISNER_BIN" "${S3_PREFIX}/bin/gleisner" --region "$REGION"

echo "deploy: syncing packages to ${S3_PREFIX}/pkgs/" >&2
aws s3 sync "$PKGS_DIR" "${S3_PREFIX}/pkgs/" --region "$REGION" --quiet

echo "deploy: syncing stdlib to ${S3_PREFIX}/std/" >&2
aws s3 sync "$STDLIB_DIR" "${S3_PREFIX}/std/" --region "$REGION" --quiet

# Upload the gleisner sandbox-init binary too (needed for the sandbox runtime)
SANDBOX_INIT="$(dirname "$GLEISNER_BIN")/gleisner-sandbox-init"
if [[ -f "$SANDBOX_INIT" ]]; then
    echo "deploy: uploading sandbox-init" >&2
    aws s3 cp "$SANDBOX_INIT" "${S3_PREFIX}/bin/gleisner-sandbox-init" --region "$REGION"
fi

# Upload profiles
PROFILES_DIR="$(cd "$(dirname "$0")/.." && pwd)/profiles"
if [[ -d "$PROFILES_DIR" ]]; then
    echo "deploy: syncing profiles" >&2
    aws s3 sync "$PROFILES_DIR" "${S3_PREFIX}/profiles/" --region "$REGION" --quiet
fi

echo "deploy: upload complete" >&2

# ── Step 3: Generate user-data ────────────────────────────────────────
PACKAGES_FLAG=""
if [[ -n "$PACKAGES" ]]; then
    PACKAGES_FLAG="--packages ${PACKAGES}"
fi

USER_DATA=$(cat <<USERDATA
#!/bin/bash
set -euo pipefail
exec > /var/log/gleisner-deploy.log 2>&1

echo "gleisner-deploy: starting at \$(date -Iseconds)"

# Fedora 42 (kernel 6.18) — full Landlock V7 audit support.
# Install AWS CLI + sandbox dependencies.
dnf install -y -q awscli2 nftables passt 2>/dev/null || dnf install -y -q awscli nftables passt 2>/dev/null || true
if ! command -v aws &>/dev/null; then
    dnf install -y -q python3-pip && pip3 install awscli 2>/dev/null || true
fi

# Create working directory
WORK_DIR="/opt/gleisner-session"
mkdir -p "\${WORK_DIR}"
cd "\${WORK_DIR}"

# Download gleisner binary
aws s3 cp "${S3_PREFIX}/bin/gleisner" /usr/local/bin/gleisner --region ${REGION}
chmod +x /usr/local/bin/gleisner

# Download sandbox-init if available
aws s3 cp "${S3_PREFIX}/bin/gleisner-sandbox-init" /usr/local/bin/gleisner-sandbox-init --region ${REGION} || true
chmod +x /usr/local/bin/gleisner-sandbox-init 2>/dev/null || true

# Download package trees
mkdir -p pkgs std
aws s3 sync "${S3_PREFIX}/pkgs/" pkgs/ --region ${REGION} --quiet
aws s3 sync "${S3_PREFIX}/std/" std/ --region ${REGION} --quiet

# Download profiles
mkdir -p profiles
aws s3 sync "${S3_PREFIX}/profiles/" profiles/ --region ${REGION} --quiet || true

echo "gleisner-deploy: downloaded assets, running forge"

# Run forge evaluation (dry-run first to capture output)
gleisner forge \\
    --pkgs-dir pkgs \\
    --stdlib-dir std \\
    --store-dir .gleisner/forge-store \\
    --profile ${PROFILE} \\
    --output .gleisner/composed-env.json \\
    ${PACKAGES_FLAG} \\
    --dry-run > .gleisner/forge-output.json 2>.gleisner/forge-stderr.log

echo "gleisner-deploy: forge evaluation complete"

# Upload forge output
aws s3 cp .gleisner/forge-output.json "${S3_PREFIX}/forge-output.json" --region ${REGION}
aws s3 cp .gleisner/forge-stderr.log "${S3_PREFIX}/forge-stderr.log" --region ${REGION}

# Write session manifest (since we're doing dry-run, not --run)
# Variables from the deploy script are baked in; instance metadata is fetched live
INSTANCE_META=\$(curl -s -H "X-aws-ec2-metadata-token: \$(curl -s -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/instance-id 2>/dev/null || echo "unknown")
cat > .gleisner/session-manifest.json <<EOF_MANIFEST
{
  "schema": "gleisner.dev/session-manifest/v1",
  "session": {
    "session_id": "${SESSION_ID}",
    "started_at": "\$(date -Iseconds)",
    "type": "forge-evaluate",
    "instance_id": "\${INSTANCE_META}",
    "instance_type": "${INSTANCE_TYPE}",
    "region": "${REGION}"
  },
  "forge": {
    "packages_evaluated": true,
    "profile": "${PROFILE}",
    "output_uri": "${S3_PREFIX}/forge-output.json"
  },
  "status": "complete"
}
EOF_MANIFEST

# Upload session manifest
aws s3 cp .gleisner/session-manifest.json "${S3_PREFIX}/manifest.json" --region ${REGION}

echo "gleisner-deploy: manifest uploaded to ${S3_PREFIX}/manifest.json"
echo "gleisner-deploy: complete at \$(date -Iseconds)"

# Signal completion by creating a marker file
echo "done" | aws s3 cp - "${S3_PREFIX}/.complete" --region ${REGION}

# Shut down (the instance will terminate if configured to)
shutdown -h +1 "gleisner session complete"
USERDATA
)

# ── Step 4: Launch EC2 instance ───────────────────────────────────────
# Resolve latest Fedora 42 Cloud AMI (kernel 6.18 — full Landlock V7 support)
echo "deploy: resolving latest Fedora 42 AMI in ${REGION}..." >&2
AMI_ID=$(aws ec2 describe-images \
    --region "$REGION" \
    --owners 125523088429 \
    --filters "Name=name,Values=Fedora-Cloud-Base-AmazonEC2.x86_64-42-*" \
              "Name=architecture,Values=x86_64" \
              "Name=state,Values=available" \
    --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' \
    --output text)

if [[ -z "$AMI_ID" || "$AMI_ID" == "None" ]]; then
    echo "error: could not find Fedora 42 AMI in ${REGION}" >&2
    exit 1
fi
echo "deploy: using AMI ${AMI_ID}" >&2

echo "deploy: launching EC2 instance (${INSTANCE_TYPE})..." >&2

LAUNCH_ARGS=(
    --image-id "$AMI_ID"
    --instance-type "$INSTANCE_TYPE"
    --region "$REGION"
    --instance-initiated-shutdown-behavior terminate
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${SESSION_ID}},{Key=gleisner-session,Value=true}]"
    --user-data "$USER_DATA"
    --metadata-options "HttpTokens=required,HttpEndpoint=enabled"
)

if [[ -n "$KEY_NAME" ]]; then
    LAUNCH_ARGS+=(--key-name "$KEY_NAME")
fi

# Instance profile for S3 access — run deploy/setup-iam.sh first
INSTANCE_PROFILE="${GLEISNER_INSTANCE_PROFILE:-gleisner-session-profile}"
LAUNCH_ARGS+=(--iam-instance-profile "Name=${INSTANCE_PROFILE}")

INSTANCE_ID=$(aws ec2 run-instances \
    "${LAUNCH_ARGS[@]}" \
    --query 'Instances[0].InstanceId' \
    --output text)

echo "deploy: instance=${INSTANCE_ID} launching" >&2

# ── Step 5: Wait for completion ───────────────────────────────────────
echo "deploy: waiting for session to complete (checking S3 for manifest)..." >&2

MAX_WAIT=600  # 10 minutes
ELAPSED=0
POLL_INTERVAL=15

while [[ $ELAPSED -lt $MAX_WAIT ]]; do
    if aws s3 ls "${S3_PREFIX}/.complete" --region "$REGION" >/dev/null 2>&1; then
        echo "deploy: session complete after ${ELAPSED}s" >&2
        break
    fi

    # Check if instance is still running
    STATE=$(aws ec2 describe-instances \
        --instance-ids "$INSTANCE_ID" \
        --region "$REGION" \
        --query 'Reservations[0].Instances[0].State.Name' \
        --output text 2>/dev/null || echo "unknown")

    if [[ "$STATE" == "terminated" || "$STATE" == "shutting-down" ]]; then
        # Instance shut down — check if manifest exists
        if aws s3 ls "${S3_PREFIX}/manifest.json" --region "$REGION" >/dev/null 2>&1; then
            echo "deploy: instance terminated, manifest found" >&2
            break
        else
            echo "error: instance terminated without producing manifest" >&2
            echo "deploy: check logs: aws s3 cp ${S3_PREFIX}/forge-stderr.log -" >&2
            exit 1
        fi
    fi

    sleep "$POLL_INTERVAL"
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
    echo "deploy: waiting... (${ELAPSED}s, instance=${STATE})" >&2
done

if [[ $ELAPSED -ge $MAX_WAIT ]]; then
    echo "error: timed out after ${MAX_WAIT}s" >&2
    echo "deploy: instance ${INSTANCE_ID} may still be running" >&2
    exit 1
fi

# ── Step 6: Download results ──────────────────────────────────────────
echo "deploy: downloading results..." >&2

RESULTS_DIR=".gleisner/remote-sessions/${SESSION_ID}"
mkdir -p "$RESULTS_DIR"

aws s3 cp "${S3_PREFIX}/manifest.json" "${RESULTS_DIR}/manifest.json" --region "$REGION"
aws s3 cp "${S3_PREFIX}/forge-output.json" "${RESULTS_DIR}/forge-output.json" --region "$REGION" 2>/dev/null || true
aws s3 cp "${S3_PREFIX}/forge-stderr.log" "${RESULTS_DIR}/forge-stderr.log" --region "$REGION" 2>/dev/null || true

echo "deploy: results saved to ${RESULTS_DIR}/" >&2

# Print manifest to stdout (for management Claude to consume)
cat "${RESULTS_DIR}/manifest.json"

# ── Cleanup ───────────────────────────────────────────────────────────
if [[ "$CLEANUP" == "true" ]]; then
    echo "deploy: cleaning up S3 session data..." >&2
    aws s3 rm "${S3_PREFIX}/" --recursive --region "$REGION" --quiet 2>/dev/null || true
fi

echo "deploy: done. session_id=${SESSION_ID}" >&2
