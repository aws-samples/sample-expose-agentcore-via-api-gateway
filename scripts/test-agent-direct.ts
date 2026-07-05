#!/usr/bin/env ts-node
/**
 * Direct AgentCore Runtime invocation test (JWT, bypassing the Gateway).
 *
 * Authenticates against Cognito to obtain a valid access token, then calls the
 * AgentCore Runtime data plane directly over the public internet with
 *   `Authorization: Bearer <JWT>`.
 *
 * Expected outcome: the Runtime rejects the call (AccessDeniedException /
 * 403) because the runtime's inbound authorizer is configured with
 *   customJWTAuthorizer.allowedWorkloadConfiguration.hostingEnvironments = [thisGateway]
 * A request that does not flow through the Gateway does not carry the Gateway's
 * workload identity in its identity chain, so it is denied — EVEN with a valid
 * JWT from your registered IdP. This is **expected behavior** and demonstrates
 * that the perimeter is doing its job.
 *
 * This replaces the previous aws:SourceVpc perimeter: with the VPC/proxy
 * removed, "the call must come through my Gateway" is now enforced by the
 * runtime's allowedWorkloadConfiguration rather than by a VPC-scoped resource
 * policy. The only valid path is:
 *   Client → AgentCore Gateway (CUSTOM_JWT) → REQUEST interceptor
 *          → AgentCore Runtime (workload-locked to this Gateway).
 *
 * Auto-reads AGENT_RUNTIME_ARN, USER_POOL_CLIENT_ID, and Region from
 * cdk-outputs.json, and reads test-user credentials from
 * scripts/seed-output.json (written by `npx ts-node scripts/seed-data.ts`).
 *
 * Usage:
 *   npx ts-node scripts/test-agent-direct.ts
 *   npx ts-node scripts/test-agent-direct.ts "What can you do?"
 */

import {
  CognitoIdentityProviderClient,
  InitiateAuthCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

interface CdkOutputs {
  AgentRuntimeArn?: string;
  UserPoolClientId?: string;
  GatewayUrl?: string;
  Region?: string;
}

interface SeedOutput {
  user1Password?: string;
}

function loadCdkOutputs(): CdkOutputs {
  const outputsPath = path.join(__dirname, '..', 'cdk-outputs.json');
  try {
    const raw = fs.readFileSync(outputsPath, 'utf-8');
    const outputs = JSON.parse(raw);
    const stackName = Object.keys(outputs)[0];
    return outputs[stackName] ?? {};
  } catch {
    return {};
  }
}

function loadSeedOutput(): SeedOutput {
  const seedPath = path.join(__dirname, 'seed-output.json');
  try {
    return JSON.parse(fs.readFileSync(seedPath, 'utf-8')) as SeedOutput;
  } catch {
    return {};
  }
}

const cdkOutputs = loadCdkOutputs();
const seedOutput = loadSeedOutput();

const AGENT_RUNTIME_ARN =
  process.env.AGENT_RUNTIME_ARN || cdkOutputs.AgentRuntimeArn || '';
const USER_POOL_CLIENT_ID =
  process.env.USER_POOL_CLIENT_ID || cdkOutputs.UserPoolClientId || '';
const REGION =
  process.env.AWS_REGION || cdkOutputs.Region || 'us-east-1';
const GATEWAY_URL = process.env.GATEWAY_URL || cdkOutputs.GatewayUrl || '<GatewayUrl>';
const USERNAME = process.env.USERNAME || 'user1@test.com';
const PASSWORD = process.env.PASSWORD || seedOutput.user1Password || '';
const PROMPT = process.argv[2] ?? 'Hello, are you working?';

async function getJwt(): Promise<string> {
  const cognito = new CognitoIdentityProviderClient({ region: REGION });
  const result = await cognito.send(new InitiateAuthCommand({
    ClientId: USER_POOL_CLIENT_ID,
    AuthFlow: 'USER_PASSWORD_AUTH',
    AuthParameters: { USERNAME, PASSWORD },
  }));
  const accessToken = result.AuthenticationResult?.AccessToken;
  if (!accessToken) {
    throw new Error('No AccessToken in Cognito response');
  }
  return accessToken;
}

function buildRuntimeUrl(runtimeArn: string, region: string): string {
  return (
    `https://bedrock-agentcore.${region}.amazonaws.com` +
    `/runtimes/${encodeURIComponent(runtimeArn)}` +
    `/invocations?qualifier=DEFAULT`
  );
}

function redactUsername(username: string): string {
  const at = username.indexOf('@');
  if (at > 0) {
    const local = username.slice(0, at);
    const domain = username.slice(at + 1);
    const maskedLocal =
      local.length <= 2 ? '*'.repeat(local.length) : `${local[0]}***${local[local.length - 1]}`;
    return `${maskedLocal}@${domain}`;
  }
  if (username.length <= 2) return '*'.repeat(username.length);
  return `${username[0]}***${username[username.length - 1]}`;
}

async function main(): Promise<void> {
  const missing: string[] = [];
  if (!AGENT_RUNTIME_ARN) missing.push('AGENT_RUNTIME_ARN');
  if (!USER_POOL_CLIENT_ID) missing.push('USER_POOL_CLIENT_ID');
  if (!PASSWORD) missing.push('PASSWORD (or seed-output.json with user1Password)');
  if (missing.length) {
    console.error(`ERROR: missing required input(s): ${missing.join(', ')}`);
    console.error('  Either export them, or deploy first and run scripts/seed-data.ts.');
    process.exit(1);
  }

  const sessionId = crypto.randomUUID();
  const url = buildRuntimeUrl(AGENT_RUNTIME_ARN, REGION);

  console.log('=== Direct AgentCore Runtime Invocation Test (JWT, bypassing the Gateway) ===\n');
  console.log(`  Region:           ${REGION}`);
  console.log(`  Runtime ARN:      ${AGENT_RUNTIME_ARN}`);
  console.log(`  User pool client: ${USER_POOL_CLIENT_ID}`);
  console.log(`  Username:         ${redactUsername(USERNAME)}`);
  console.log(`  Session UUID:     ${sessionId}`);
  console.log(`  URL:              ${url}`);
  console.log(`  Prompt:           "${PROMPT}"\n`);

  console.log('Authenticating against Cognito...');
  let jwt: string;
  try {
    jwt = await getJwt();
  } catch (err) {
    console.error('Failed to obtain JWT:', err instanceof Error ? err.message : err);
    process.exit(1);
  }
  console.log('  Got access_token (truncated):', jwt.slice(0, 20) + '...\n');

  console.log('Invoking AgentCore Runtime directly with the JWT (not through the Gateway)...');
  const startTime = Date.now();

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      // Any value >= 33 chars satisfies the runtime's session-id length rule;
      // the call is denied by the workload perimeter before it matters.
      'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id':
        crypto.createHash('sha256').update(`${sessionId}:direct-test`).digest('hex'),
    },
    body: JSON.stringify({ prompt: PROMPT }),
  });

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const body = await response.text();

  console.log(`\n--- Response (${elapsed}s) ---`);
  console.log(`  HTTP status: ${response.status} ${response.statusText}`);
  console.log(`  Body: ${body || '(empty)'}\n`);

  if (response.status === 403 || response.status === 401 || /AccessDenied|not allowed|workload/i.test(body)) {
    console.log('=== RESULT: denied (403 / AccessDeniedException) ===\n');
    console.log('This is the expected outcome. The Cognito JWT is valid, but the call did');
    console.log('not flow through the Gateway, so its identity chain does not include the');
    console.log('Gateway workload. The runtime\'s allowedWorkloadConfiguration rejects it.');
    console.log('The perimeter is doing its job.\n');
    console.log('Reach the agent through the only valid path — the Gateway:');
    console.log(`  curl -X POST "${GATEWAY_URL.replace(/\/$/, '')}/runtime/invocations" \\`);
    console.log('    -H "Authorization: Bearer <jwt>" \\');
    console.log('    -H "X-Session-Id: <uuid-v4>" \\');
    console.log('    -d \'{"prompt": "..."}\'');
    process.exit(0);
  }

  if (response.status >= 200 && response.status < 300) {
    console.log('=== UNEXPECTED: 2xx ===\n');
    console.log('The runtime accepted a JWT-authenticated call that bypassed the Gateway.');
    console.log('That means the workload lock is missing or misconfigured. Check:');
    console.log('  1. lib/agentcore-security-stack.ts — the CfnRuntime AllowedWorkloadConfiguration override');
    console.log('  2. Whether CloudFormation accepted AllowedWorkloadConfiguration (see deploy-time note in the stack)');
    console.log('  3. The Runtime authorizerConfiguration in the AWS console / get-agent-runtime');
    process.exit(2);
  }

  console.log('=== UNEXPECTED status code ===\n');
  console.log('Neither a denial (401/403/AccessDeniedException) nor a 2xx success.');
  console.log('Possible causes: JWT misconfiguration, runtime not yet ACTIVE, network issues.');
  process.exit(3);
}

main().catch((err) => {
  console.error('\nFatal:', err instanceof Error ? err.message : err);
  process.exit(1);
});
