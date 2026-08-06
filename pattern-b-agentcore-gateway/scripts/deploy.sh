#!/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# deploy.sh — Deploy the AgentCore Runtime Security Sample stack.
#
# Architecture (OAuth inbound + OAUTH client-credentials outbound):
#   Client → AgentCore Gateway (CUSTOM_JWT inbound, Cognito)
#          → REQUEST interceptor Lambda (JWT + UUID + composite hash + throttle)
#          → AgentCore Runtime (OAuth inbound; Gateway uses OAUTH
#            client-credentials outbound via AgentCore Identity)
#   The Runtime is locked to this Gateway via allowedWorkloadConfiguration.
#
# Usage:
#   chmod +x scripts/deploy.sh
#   ./scripts/deploy.sh
#
# Prerequisites:
#   - AWS credentials configured (aws configure / env vars / SSO)
#   - Node.js 20+ installed
#   - AWS CDK CLI installed (npm install -g aws-cdk)

set -euo pipefail

echo "============================================="
echo " AgentCore Runtime Security Sample — Deploy"
echo "============================================="
echo ""

# Step 1: Install dependencies
echo "1. Installing dependencies..."
npm install
echo ""

# Step 2: Build agent artifact with Linux ARM64 dependencies (AgentCore's platform)
# Follows: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-direct-deploy.html
echo "2. Building agent artifact (linux/aarch64 via uv)..."
rm -rf .build/agent
mkdir -p .build/agent

# Install dependencies for Linux ARM64 + Python 3.12 (matching PYTHON_3_12 runtime)
uv pip install \
  --python-platform aarch64-manylinux2014 \
  --python-version 3.12 \
  --target .build/agent \
  --only-binary=:all: \
  -r agent/requirements.txt

# Copy agent source into the package root
cp agent/handler.py .build/agent/

# Remove Python cache files — AgentCore rejects artifacts containing them
find .build/agent -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find .build/agent -name "*.pyc" -delete 2>/dev/null || true

# Set POSIX permissions required by AgentCore Runtime:
#   755 for directories and executable files (.so)
#   644 for non-executable files
find .build/agent -type d -exec chmod 755 {} +
find .build/agent -type f -exec chmod 644 {} +
find .build/agent -type f -name "*.so" -exec chmod 755 {} +

echo "   Done."
echo ""

# Step 3: Bootstrap CDK (idempotent — safe to run if already bootstrapped)
echo "3. Bootstrapping CDK (if needed)..."
npx cdk bootstrap 2>/dev/null || echo "   CDK already bootstrapped or bootstrap skipped."
echo ""

# Step 4: Deploy the stack
echo "4. Deploying AgentCoreSecurityStack..."
export CDK_DEFAULT_ACCOUNT=$(aws sts get-caller-identity --query Account --output text)
export CDK_DEFAULT_REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}
npx cdk deploy --require-approval never --outputs-file cdk-outputs.json
echo ""

# Step 5: Print stack outputs
echo "============================================="
echo " Stack Outputs"
echo "============================================="

if [ -f cdk-outputs.json ]; then
  STACK_NAME=$(node -e "const o=require('./cdk-outputs.json'); console.log(Object.keys(o)[0])")
  get_output() {
    node -e "const o=require('./cdk-outputs.json'); console.log(o['${STACK_NAME}']['$1'] || 'N/A')"
  }
  API_URL=$(get_output 'GatewayUrl')
  GATEWAY_ID=$(get_output 'GatewayId')
  GATEWAY_ARN=$(get_output 'GatewayArn')
  USER_POOL_ID=$(get_output 'UserPoolId')
  USER_POOL_CLIENT_ID=$(get_output 'UserPoolClientId')
  THROTTLE_TABLE_NAME=$(get_output 'ThrottleTableName')
  REGION=$(get_output 'Region')
  AGENT_RUNTIME_ARN=$(get_output 'AgentRuntimeArn')

  echo "  GATEWAY_URL:          ${API_URL}"
  echo "  GATEWAY_ID:           ${GATEWAY_ID}"
  echo "  GATEWAY_ARN:          ${GATEWAY_ARN}"
  echo "  USER_POOL_ID:         ${USER_POOL_ID}"
  echo "  USER_POOL_CLIENT_ID:  ${USER_POOL_CLIENT_ID}"
  echo "  THROTTLE_TABLE_NAME:  ${THROTTLE_TABLE_NAME}"
  echo "  REGION:               ${REGION}"
  echo "  AGENT_RUNTIME_ARN:    ${AGENT_RUNTIME_ARN}"
  echo ""
  echo "Export these for use with seed-data and test scripts:"
  echo ""
  echo "  export GATEWAY_URL=\"${API_URL}\""
  echo "  export GATEWAY_ID=\"${GATEWAY_ID}\""
  echo "  export GATEWAY_ARN=\"${GATEWAY_ARN}\""
  echo "  export USER_POOL_ID=\"${USER_POOL_ID}\""
  echo "  export USER_POOL_CLIENT_ID=\"${USER_POOL_CLIENT_ID}\""
  echo "  export THROTTLE_TABLE_NAME=\"${THROTTLE_TABLE_NAME}\""
  echo "  export AWS_REGION=\"${REGION}\""
  echo "  export AGENT_RUNTIME_ARN=\"${AGENT_RUNTIME_ARN}\""

else
  echo "  (cdk-outputs.json not found — check CDK deploy output above)"
fi

echo ""
echo "Deploy complete."
