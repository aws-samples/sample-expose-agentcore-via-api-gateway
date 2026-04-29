#!/bin/bash
# deploy.sh — Deploy the AgentCore Runtime Security Sample stack.
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
  # Extract outputs from the CDK outputs file
  STACK_NAME=$(node -e "const o=require('./cdk-outputs.json'); console.log(Object.keys(o)[0])")
  API_URL=$(node -e "const o=require('./cdk-outputs.json'); console.log(o['${STACK_NAME}'].ApiUrl || 'N/A')")
  USER_POOL_ID=$(node -e "const o=require('./cdk-outputs.json'); console.log(o['${STACK_NAME}'].UserPoolId || 'N/A')")
  USER_POOL_CLIENT_ID=$(node -e "const o=require('./cdk-outputs.json'); console.log(o['${STACK_NAME}'].UserPoolClientId || 'N/A')")
  THROTTLE_TABLE_NAME=$(node -e "const o=require('./cdk-outputs.json'); console.log(o['${STACK_NAME}'].ThrottleTableName || 'N/A')")
  REGION=$(node -e "const o=require('./cdk-outputs.json'); console.log(o['${STACK_NAME}'].Region || 'N/A')")
  VPC_ID=$(node -e "const o=require('./cdk-outputs.json'); console.log(o['${STACK_NAME}'].VpcId || 'N/A')")

  echo "  API_URL:              ${API_URL}"
  echo "  USER_POOL_ID:         ${USER_POOL_ID}"
  echo "  USER_POOL_CLIENT_ID:  ${USER_POOL_CLIENT_ID}"
  echo "  THROTTLE_TABLE_NAME:  ${THROTTLE_TABLE_NAME}"
  echo "  REGION:               ${REGION}"
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
