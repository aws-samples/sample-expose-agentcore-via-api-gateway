#!/usr/bin/env ts-node
/**
 * Direct AgentCore Runtime invocation test (JWT, from outside the VPC).
 *
 * Authenticates against Cognito to obtain a valid id_token, then calls the
 * AgentCore Runtime data plane directly over the public internet with
 *   `Authorization: Bearer <JWT>`.
 *
 * Expected outcome: the Runtime resource-based policy rejects the call with
 *   `AccessDeniedException`
 * because the request does not traverse this stack's VPC endpoint and
 * therefore does not carry `aws:SourceVpc` in its request context. This is
 * **expected behavior** and demonstrates that the perimeter is doing its
 * job — even a valid JWT from your registered IdP cannot reach the agent
 * if the call originates from outside your VPC.
 *
 * The only valid path remains:
 *   API Gateway → Lambda Authorizer → Proxy Lambda (in VPC)
 *               → bedrock-agentcore VPC endpoint → AgentCore Runtime
 *
 * Auto-reads AGENT_RUNTIME_ARN, USER_POOL_CLIENT_ID, and AWS_REGION from
 * cdk-outputs.json, and reads test-user credentials from
 * scripts/seed-output.json (written by `npx ts-node scripts/seed-data.ts`).
 *
 * Usage:
 *   npx ts-node scripts/test-agent-direct.ts
 *
 *   # Or with overrides:
 *   export AGENT_RUNTIME_ARN=<arn>
 *   export USER_POOL_CLIENT_ID=<id>
 *   export AWS_REGION=<region>
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
  const idToken = result.AuthenticationResult?.IdToken;
  if (!idToken) {
    throw new Error('No IdToken in Cognito response');
  }
  return idToken;
}

function buildRuntimeUrl(runtimeArn: string, region: string): string {
  return (
    `https://bedrock-agentcore.${region}.amazonaws.com` +
    `/runtimes/${encodeURIComponent(runtimeArn)}` +
    `/invocations?qualifier=DEFAULT`
  );
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

  console.log('=== Direct AgentCore Runtime Invocation Test (JWT, from laptop) ===\n');
  console.log(`  Region:           ${REGION}`);
  console.log(`  Runtime ARN:      ${AGENT_RUNTIME_ARN}`);
  console.log(`  User pool client: ${USER_POOL_CLIENT_ID}`);
  console.log(`  Username:         ${USERNAME}`);
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
  console.log('  Got id_token (truncated):', jwt.slice(0, 20) + '...\n');

  console.log('Invoking AgentCore Runtime directly with the JWT (no VPC endpoint)...');
  const startTime = Date.now();

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
      'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id':
        // Pad to >= 33 chars to satisfy the runtime's session-id length requirement.
        // (The full sample uses sha256(uuid:jwtSub) which is 64 chars; here we just
        // need any value long enough — the call won't get past the resource policy
        // anyway in a properly deployed stack.)
        crypto.createHash('sha256').update(`${sessionId}:direct-test`).digest('hex'),
    },
    body: JSON.stringify({ prompt: PROMPT }),
  });

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  const body = await response.text();

  console.log(`\n--- Response (${elapsed}s) ---`);
  console.log(`  HTTP status: ${response.status} ${response.statusText}`);
  console.log(`  Body: ${body || '(empty)'}\n`);

  if (response.status === 403 || /AccessDenied/i.test(body)) {
    console.log('=== RESULT: 403 / AccessDeniedException ===\n');
    console.log('This is the expected outcome. The Cognito JWT is valid, but the call');
    console.log('did not traverse this stack\'s VPC endpoint, so `aws:SourceVpc` is not');
    console.log('populated in the request context. The Runtime resource-based policy');
    console.log('denies the call. The perimeter is doing its job.\n');
    console.log('Reach the agent through the documented path:');
    console.log('  curl -X POST "${API_URL}invoke" \\');
    console.log('    -H "Authorization: Bearer <jwt>" \\');
    console.log('    -H "X-Session-Id: <uuid-v4>" \\');
    console.log('    -d \'{"prompt": "..."}\'');
    process.exit(0);
  }

  if (response.status >= 200 && response.status < 300) {
    console.log('=== UNEXPECTED: 2xx ===\n');
    console.log('The runtime accepted a JWT-authenticated call from outside the VPC.');
    console.log('That means the resource-based policy is missing, misconfigured, or the');
    console.log('runtime is not OAuth-inbound. Check:');
    console.log('  1. lib/agentcore-security-stack.ts — RuntimeResourcePolicy / RuntimeEndpointResourcePolicy');
    console.log('  2. CloudFormation deployment status of the AwsCustomResource resources');
    console.log('  3. The Runtime\'s authorizerConfiguration in the AWS console');
    process.exit(2);
  }

  console.log('=== UNEXPECTED status code ===\n');
  console.log('Neither a denial (403/AccessDeniedException) nor a 2xx success.');
  console.log('Possible causes: JWT misconfiguration, runtime not yet ACTIVE, network issues.');
  process.exit(3);
}

main().catch((err) => {
  console.error('\nFatal:', err instanceof Error ? err.message : err);
  process.exit(1);
});
