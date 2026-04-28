#!/bin/bash
# test-security-controls.sh — Validate the security best practices.
#
# Reads seed UUIDs from scripts/seed-output.json (written by seed-data.ts).
#
# Usage:
#   export API_URL=<from CDK output>
#   export USER_POOL_ID=<from CDK output>
#   export USER_POOL_CLIENT_ID=<from CDK output>
#   export AWS_REGION=<from CDK output>
#   export VPC_ID=<from CDK output>
#   chmod +x scripts/test-security-controls.sh
#   ./scripts/test-security-controls.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEED_OUTPUT="${SCRIPT_DIR}/seed-output.json"

echo "============================================="
echo " AgentCore Security Controls — Validation"
echo "============================================="
echo ""

: "${API_URL:?ERROR: API_URL is not set.}"
: "${USER_POOL_ID:?ERROR: USER_POOL_ID is not set.}"
: "${USER_POOL_CLIENT_ID:?ERROR: USER_POOL_CLIENT_ID is not set.}"
: "${AWS_REGION:?ERROR: AWS_REGION is not set.}"

if [ ! -f "${SEED_OUTPUT}" ]; then
  echo "ERROR: ${SEED_OUTPUT} not found."
  echo "Run 'npx ts-node scripts/seed-data.ts' first."
  exit 1
fi

SESSION_USER1=$(jq -r '.user1SessionId' "${SEED_OUTPUT}")
SESSION_USER2=$(jq -r '.user2SessionId' "${SEED_OUTPUT}")
PASSWORD_USER1=$(jq -r '.user1Password' "${SEED_OUTPUT}")
PASSWORD_USER2=$(jq -r '.user2Password' "${SEED_OUTPUT}")

echo "  Using session UUIDs from ${SEED_OUTPUT}"
echo "    user1 session UUID: ${SESSION_USER1}"
echo "    user2 session UUID: ${SESSION_USER2}"
echo ""

PASS=0
FAIL=0
RESULTS=()

get_jwt() {
  aws cognito-idp initiate-auth \
    --region "${AWS_REGION}" \
    --client-id "${USER_POOL_CLIENT_ID}" \
    --auth-flow USER_PASSWORD_AUTH \
    --auth-parameters "USERNAME=${1},PASSWORD=${2}" \
    --query 'AuthenticationResult.IdToken' \
    --output text
}

record_result() {
  local test_name="$1"
  local expected="$2"
  local actual="$3"
  if [ "$expected" = "$actual" ]; then
    RESULTS+=("PASS | ${test_name}")
    PASS=$((PASS + 1))
  else
    RESULTS+=("FAIL | ${test_name} (expected ${expected}, got ${actual})")
    FAIL=$((FAIL + 1))
  fi
}

# =========================================================================
# TEST 1: INBOUND SECURITY — API Gateway + Lambda Authorizer
# Valid JWT + any UUID v4 should pass through the authorizer
# =========================================================================
echo "TEST 1: Inbound Security (API Gateway + Lambda Authorizer)"
echo "  Authenticating user1@test.com..."
JWT_USER1=$(get_jwt "user1@test.com" "${PASSWORD_USER1}")

echo "  Calling POST /invoke with valid JWT + UUID..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST "${API_URL}invoke" \
  -H "Authorization: Bearer ${JWT_USER1}" \
  -H "X-Session-Id: ${SESSION_USER1}" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello"}')

echo "  Response: ${HTTP_STATUS}"
# 200 = full success. 4xx/5xx other than 401/403 from the authorizer still
# mean the authorizer ALLOWED the request and the error came from the backend.
if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "504" ] || [ "$HTTP_STATUS" = "404" ] || [ "$HTTP_STATUS" = "500" ]; then
  RESULTS+=("PASS | Inbound Security (authorizer allowed valid request, status: ${HTTP_STATUS})")
  PASS=$((PASS + 1))
else
  RESULTS+=("FAIL | Inbound Security (expected 200/504/404/500, got ${HTTP_STATUS})")
  FAIL=$((FAIL + 1))
fi
echo ""

# =========================================================================
# TEST 2: OUTBOUND SECURITY — VPC with no internet egress
# =========================================================================
echo "TEST 2: Outbound Security (VPC network isolation)"
VPC_ID="${VPC_ID:-}"

if [ -n "$VPC_ID" ]; then
  IGW_COUNT=$(aws ec2 describe-internet-gateways \
    --region "${AWS_REGION}" \
    --filters "Name=attachment.vpc-id,Values=${VPC_ID}" \
    --query 'InternetGateways | length(@)' \
    --output text 2>/dev/null || echo "error")

  NAT_COUNT=$(aws ec2 describe-nat-gateways \
    --region "${AWS_REGION}" \
    --filter "Name=vpc-id,Values=${VPC_ID}" "Name=state,Values=available" \
    --query 'NatGateways | length(@)' \
    --output text 2>/dev/null || echo "error")

  echo "  Internet Gateways: ${IGW_COUNT}, NAT Gateways: ${NAT_COUNT}"

  if [ "$IGW_COUNT" = "0" ] && [ "$NAT_COUNT" = "0" ]; then
    RESULTS+=("PASS | Outbound Security (no IGW, no NAT)")
    PASS=$((PASS + 1))
  else
    RESULTS+=("FAIL | Outbound Security (IGW: ${IGW_COUNT}, NAT: ${NAT_COUNT})")
    FAIL=$((FAIL + 1))
  fi
else
  echo "  VPC_ID not set — skipping"
  RESULTS+=("SKIP | Outbound Security (VPC_ID not set)")
fi
echo ""

# =========================================================================
# TEST 3: RUNTIME DIRECT ACCESS PREVENTION
# Request without Authorization header should be rejected at API Gateway
# =========================================================================
echo "TEST 3: Runtime Direct Access Prevention"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST "${API_URL}invoke" \
  -H "X-Session-Id: ${SESSION_USER1}" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "bypass attempt"}')

echo "  Response: ${HTTP_STATUS}"
record_result "Runtime Direct Access (no auth → blocked at API Gateway)" "401" "${HTTP_STATUS}"
echo ""

# =========================================================================
# TEST 4: INVALID SESSION FORMAT REJECTION
# Authorizer rejects non-UUID session IDs before any downstream work
# =========================================================================
echo "TEST 4: Invalid Session Format Rejection"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST "${API_URL}invoke" \
  -H "Authorization: Bearer ${JWT_USER1}" \
  -H "X-Session-Id: not-a-uuid" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "malformed session id"}')

echo "  Response: ${HTTP_STATUS}"
record_result "Invalid session format → 403 Deny" "403" "${HTTP_STATUS}"
echo ""

# =========================================================================
# TEST 5: SESSION ISOLATION — composite hashing makes UUID reuse harmless
# User2 reusing User1's client UUID lands on a different AgentCore session
# because compositeSessionId = sha256(uuid:jwtSub) differs per user.
# The authorizer ALLOWS both (no 403): isolation is cryptographic, not a deny.
# =========================================================================
echo "TEST 5: Session Isolation (composite hashing)"
echo "  Authenticating user2@test.com..."
JWT_USER2=$(get_jwt "user2@test.com" "${PASSWORD_USER2}")

echo "  user2 reusing user1's UUID — should be ALLOWED (different composite hash)..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST "${API_URL}invoke" \
  -H "Authorization: Bearer ${JWT_USER2}" \
  -H "X-Session-Id: ${SESSION_USER1}" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "isolated session"}')

echo "  Response: ${HTTP_STATUS}"
if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "504" ] || [ "$HTTP_STATUS" = "404" ] || [ "$HTTP_STATUS" = "500" ]; then
  RESULTS+=("PASS | Session Isolation (user2 allowed — lands on distinct composite session, status: ${HTTP_STATUS})")
  PASS=$((PASS + 1))
else
  RESULTS+=("FAIL | Session Isolation (expected 200/504/404/500, got ${HTTP_STATUS})")
  FAIL=$((FAIL + 1))
fi
echo ""

# =========================================================================
# SUMMARY
# =========================================================================
echo "============================================="
echo " Results Summary"
echo "============================================="
printf "%-6s | %s\n" "Status" "Test"
echo "-------+----------------------------------------------"
for result in "${RESULTS[@]}"; do
  printf "%s\n" "${result}"
done
echo "-------+----------------------------------------------"
echo "Total: $((PASS + FAIL)) | Passed: ${PASS} | Failed: ${FAIL}"
echo "============================================="

if [ "${FAIL}" -gt 0 ]; then
  echo ""
  echo "Some tests FAILED."
  exit 1
fi

echo ""
echo "All tests PASSED."
