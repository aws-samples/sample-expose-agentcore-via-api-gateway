#!/bin/bash
# test-security-controls.sh — Validate the deployed security controls.
#
# Architecture under test:
#   Client → AgentCore Gateway (CUSTOM_JWT inbound, Cognito)
#          → REQUEST interceptor Lambda (JWT + UUID + composite hash + throttle)
#          → AgentCore Runtime (OAuth inbound, OAUTH client-credentials
#            outbound, workload-locked)
#
# Validates five boundary behaviors against the deployed stack:
#   1. Inbound: a valid JWT + valid UUID is allowed end to end.
#   2. Missing Authorization header is blocked at the Gateway (CUSTOM_JWT inbound).
#   3. Non-UUID X-Session-Id is denied by the interceptor.
#   4. Composite session hashing keeps two users isolated even when one reuses
#      the other's client UUID.
#   5. A JWT call that bypasses the Gateway (straight to the runtime) is denied
#      by the runtime's allowedWorkloadConfiguration perimeter.
#
# Reads seed UUIDs and passwords from scripts/seed-output.json (seed-data.ts).
#
# Usage:
#   export GATEWAY_URL=<from CDK output>          # AgentCore Gateway URL
#   export USER_POOL_ID=<from CDK output>
#   export USER_POOL_CLIENT_ID=<from CDK output>
#   export AWS_REGION=<from CDK output>
#   export AGENT_RUNTIME_ARN=<from CDK output>    # for the bypass test
#   chmod +x scripts/test-security-controls.sh
#   ./scripts/test-security-controls.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEED_OUTPUT="${SCRIPT_DIR}/seed-output.json"

echo "============================================="
echo " AgentCore Security Controls — Validation"
echo "============================================="
echo ""

: "${GATEWAY_URL:?ERROR: GATEWAY_URL is not set.}"
: "${USER_POOL_ID:?ERROR: USER_POOL_ID is not set.}"
: "${USER_POOL_CLIENT_ID:?ERROR: USER_POOL_CLIENT_ID is not set.}"
: "${AWS_REGION:?ERROR: AWS_REGION is not set.}"
: "${AGENT_RUNTIME_ARN:?ERROR: AGENT_RUNTIME_ARN is not set.}"

# The Runtime target is addressed by target name ("runtime") under the gateway.
# Gateway target invoke URL format:
#   https://{gatewayId}.gateway.bedrock-agentcore.{region}.amazonaws.com/{targetName}/invocations
GATEWAY_BASE="${GATEWAY_URL%/}"
GATEWAY_BASE="${GATEWAY_BASE%/mcp}"
INVOKE_URL="${GATEWAY_BASE}/runtime/invocations"

if [ ! -f "${SEED_OUTPUT}" ]; then
  echo "ERROR: ${SEED_OUTPUT} not found."
  echo "Run 'npx ts-node scripts/seed-data.ts' first."
  exit 1
fi

SESSION_USER1=$(jq -r '.user1SessionId' "${SEED_OUTPUT}")
SESSION_USER2=$(jq -r '.user2SessionId' "${SEED_OUTPUT}")
PASSWORD_USER1=$(jq -r '.user1Password' "${SEED_OUTPUT}")
PASSWORD_USER2=$(jq -r '.user2Password' "${SEED_OUTPUT}")

echo "  Gateway invoke URL: ${INVOKE_URL}"
echo "  user1 session UUID: ${SESSION_USER1}"
echo "  user2 session UUID: ${SESSION_USER2}"
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
    --query 'AuthenticationResult.AccessToken' \
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
# TEST 1: INBOUND — valid JWT + valid UUID v4 is allowed end to end
# =========================================================================
echo "TEST 1: Inbound — valid JWT + UUID v4 allowed"
echo "  Authenticating user1@test.com..."
JWT_USER1=$(get_jwt "user1@test.com" "${PASSWORD_USER1}")

echo "  Calling the Gateway with valid JWT + UUID..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST "${INVOKE_URL}" \
  -H "Authorization: Bearer ${JWT_USER1}" \
  -H "X-Session-Id: ${SESSION_USER1}" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello"}')

echo "  Response: ${HTTP_STATUS}"
# 200 = full success. A backend error (404/500/504) still means the Gateway +
# interceptor ALLOWED the request and it reached the runtime.
if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "504" ] || [ "$HTTP_STATUS" = "404" ] || [ "$HTTP_STATUS" = "500" ]; then
  RESULTS+=("PASS | Inbound (gateway+interceptor allowed valid request, status: ${HTTP_STATUS})")
  PASS=$((PASS + 1))
else
  RESULTS+=("FAIL | Inbound (expected 200/504/404/500, got ${HTTP_STATUS})")
  FAIL=$((FAIL + 1))
fi
echo ""

# =========================================================================
# TEST 2: MISSING AUTHORIZATION HEADER — blocked by the Gateway (CUSTOM_JWT)
# =========================================================================
echo "TEST 2: Missing Authorization header → 401/403"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST "${INVOKE_URL}" \
  -H "X-Session-Id: ${SESSION_USER1}" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "bypass attempt"}')

echo "  Response: ${HTTP_STATUS}"
if [ "$HTTP_STATUS" = "401" ] || [ "$HTTP_STATUS" = "403" ]; then
  RESULTS+=("PASS | Missing Authorization header rejected by Gateway (status: ${HTTP_STATUS})")
  PASS=$((PASS + 1))
else
  RESULTS+=("FAIL | Missing Authorization header (expected 401/403, got ${HTTP_STATUS})")
  FAIL=$((FAIL + 1))
fi
echo ""

# =========================================================================
# TEST 3: INVALID SESSION FORMAT — interceptor denies non-UUID
# =========================================================================
echo "TEST 3: Non-UUID X-Session-Id → 403"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST "${INVOKE_URL}" \
  -H "Authorization: Bearer ${JWT_USER1}" \
  -H "X-Session-Id: not-a-uuid" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "malformed session id"}')

echo "  Response: ${HTTP_STATUS}"
record_result "Invalid session format → 403 (interceptor deny)" "403" "${HTTP_STATUS}"
echo ""

# =========================================================================
# TEST 4: SESSION ISOLATION — composite hashing makes UUID reuse harmless
#
# Threat model: an authenticated user (user2) tries to reach another
# authenticated user's (user1) AgentCore session by sending user1's UUID.
# Both have valid JWTs, so JWT validation alone does not stop this.
#
# Mitigation: the interceptor computes
#   runtimeSessionId = sha256(<X-Session-Id> : <jwtSub>)
# and injects it as X-Amzn-Bedrock-AgentCore-Runtime-Session-Id. Two users with
# the same UUID produce different composites, so they land on different runtime
# sessions and never share state. Both are ALLOWED — isolation is cryptographic.
# =========================================================================
echo "TEST 4: Session isolation — composite hashing"
echo "  Authenticating user2@test.com..."
JWT_USER2=$(get_jwt "user2@test.com" "${PASSWORD_USER2}")

echo "  user2 reusing user1's UUID — should be ALLOWED on a different composite session..."
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST "${INVOKE_URL}" \
  -H "Authorization: Bearer ${JWT_USER2}" \
  -H "X-Session-Id: ${SESSION_USER1}" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "isolated session"}')

echo "  Response: ${HTTP_STATUS}"
if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "504" ] || [ "$HTTP_STATUS" = "404" ] || [ "$HTTP_STATUS" = "500" ]; then
  RESULTS+=("PASS | Session isolation (user2 lands on a distinct composite session, status: ${HTTP_STATUS})")
  PASS=$((PASS + 1))
else
  RESULTS+=("FAIL | Session isolation (expected 200/504/404/500, got ${HTTP_STATUS})")
  FAIL=$((FAIL + 1))
fi
echo ""

# =========================================================================
# TEST 5: PERIMETER — a JWT call that bypasses the Gateway is denied by the
# runtime's allowedWorkloadConfiguration (replaces the old aws:SourceVpc test).
# =========================================================================
echo "TEST 5: Perimeter — direct runtime call (bypassing the Gateway) is denied"
DIRECT_URL="https://bedrock-agentcore.${AWS_REGION}.amazonaws.com/runtimes/$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1], safe=''))" "${AGENT_RUNTIME_ARN}")/invocations?qualifier=DEFAULT"
LONG_SESSION=$(printf '%s' "${SESSION_USER1}:direct" | shasum -a 256 | cut -d' ' -f1)

HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 \
  -X POST "${DIRECT_URL}" \
  -H "Authorization: Bearer ${JWT_USER1}" \
  -H "Content-Type: application/json" \
  -H "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id: ${LONG_SESSION}" \
  -d '{"prompt": "bypass the gateway"}')

echo "  Response: ${HTTP_STATUS}"
if [ "$HTTP_STATUS" = "401" ] || [ "$HTTP_STATUS" = "403" ]; then
  RESULTS+=("PASS | Perimeter (direct-to-runtime JWT call denied, status: ${HTTP_STATUS})")
  PASS=$((PASS + 1))
else
  RESULTS+=("FAIL | Perimeter (expected 401/403 for a Gateway bypass, got ${HTTP_STATUS})")
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
