#!/bin/bash
# cleanup.sh — Tear down the AgentCore Runtime Security Sample stack.
#
# Usage:
#   chmod +x scripts/cleanup.sh
#   ./scripts/cleanup.sh

set -euo pipefail

echo "============================================="
echo " AgentCore Runtime Security Sample — Cleanup"
echo "============================================="
echo ""

echo "Destroying AgentCoreSecurityStack..."
npx cdk destroy --force

echo ""
echo "Stack destroyed. All resources have been removed."
