#!/bin/bash
# deploy.sh — Deploy the AgentCore Runtime Security Sample stack.
#
# Architecture:
#   API Gateway → Lambda Authorizer → Proxy Lambda (in private VPC)
#   → bedrock-agentcore VPC endpoint → AgentCore Runtime (OAuth inbound)
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
  API_URL=$(get_output 'ApiUrl')
  USER_POOL_ID=$(get_output 'UserPoolId')
  USER_POOL_CLIENT_ID=$(get_output 'UserPoolClientId')
  THROTTLE_TABLE_NAME=$(get_output 'ThrottleTableName')
  REGION=$(get_output 'Region')
  AGENT_RUNTIME_ARN=$(get_output 'AgentRuntimeArn')
  VPC_ID=$(get_output 'VpcId')

  echo "  API_URL:              ${API_URL}"
  echo "  USER_POOL_ID:         ${USER_POOL_ID}"
  echo "  USER_POOL_CLIENT_ID:  ${USER_POOL_CLIENT_ID}"
  echo "  THROTTLE_TABLE_NAME:  ${THROTTLE_TABLE_NAME}"
  echo "  REGION:               ${REGION}"
  echo "  AGENT_RUNTIME_ARN:    ${AGENT_RUNTIME_ARN}"
  echo "  VPC_ID:               ${VPC_ID}"
  echo ""
  echo "Export these for use with seed-data and test scripts:"
  echo ""
  echo "  export API_URL=\"${API_URL}\""
  echo "  export USER_POOL_ID=\"${USER_POOL_ID}\""
  echo "  export USER_POOL_CLIENT_ID=\"${USER_POOL_CLIENT_ID}\""
  echo "  export THROTTLE_TABLE_NAME=\"${THROTTLE_TABLE_NAME}\""
  echo "  export AWS_REGION=\"${REGION}\""
  echo "  export VPC_ID=\"${VPC_ID}\""

else
  echo "  (cdk-outputs.json not found — check CDK deploy output above)"
fi

echo ""
echo "Deploy complete."
