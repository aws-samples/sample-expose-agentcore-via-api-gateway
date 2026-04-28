#!/usr/bin/env ts-node
/**
 * Direct AgentCore Runtime invocation test.
 *
 * Bypasses API Gateway, Lambda Authorizer, proxy Lambda, and VPC entirely.
 * Calls the AgentCore Runtime directly using your local AWS credentials
 * to isolate whether the agent itself works.
 *
 * Auto-reads AGENT_RUNTIME_ARN from cdk-outputs.json if available.
 *
 * Usage:
 *   npx ts-node scripts/test-agent-direct.ts
 *
 *   # Or with explicit ARN:
 *   export AGENT_RUNTIME_ARN=<arn>
 *   npx ts-node scripts/test-agent-direct.ts
 *
 *   # Custom prompt:
 *   npx ts-node scripts/test-agent-direct.ts "What can you do?"
 */

import {
  BedrockAgentCoreClient,
  InvokeAgentRuntimeCommand,
} from '@aws-sdk/client-bedrock-agentcore';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

function loadArnFromCdkOutputs(): string | undefined {
  const outputsPath = path.join(__dirname, '..', 'cdk-outputs.json');
  try {
    const raw = fs.readFileSync(outputsPath, 'utf-8');
    const outputs = JSON.parse(raw);
    const stackName = Object.keys(outputs)[0];
    return outputs[stackName]?.AgentRuntimeArn;
  } catch {
    return undefined;
  }
}

const AGENT_RUNTIME_ARN = process.env.AGENT_RUNTIME_ARN || loadArnFromCdkOutputs() || '';
const REGION = process.env.AWS_REGION ?? 'us-west-2';
const PROMPT = process.argv[2] ?? 'Hello, are you working?';

async function main(): Promise<void> {
  if (!AGENT_RUNTIME_ARN) {
    console.error('ERROR: AGENT_RUNTIME_ARN not found.');
    console.error('  Either export it: export AGENT_RUNTIME_ARN=<arn>');
    console.error('  Or deploy first so cdk-outputs.json exists.');
    process.exit(1);
  }

  const sessionId = crypto.randomUUID();

  console.log('=== Direct AgentCore Runtime Invocation Test ===\n');
  console.log(`  Region:      ${REGION}`);
  console.log(`  Runtime ARN: ${AGENT_RUNTIME_ARN}`);
  console.log(`  Session ID:  ${sessionId}`);
  console.log(`  Prompt:      "${PROMPT}"\n`);

  const client = new BedrockAgentCoreClient({
    region: REGION,
    requestHandler: {
      requestTimeout: 120_000, // 2 min — AgentCore cold starts can be slow
    } as any,
  });

  const payload = JSON.stringify({ prompt: PROMPT });

  console.log('Invoking runtime (this may take up to 2 minutes on cold start)...\n');
  const startTime = Date.now();

  try {
    const response = await client.send(new InvokeAgentRuntimeCommand({
      agentRuntimeArn: AGENT_RUNTIME_ARN,
      contentType: 'application/json',
      accept: 'application/json',
      runtimeSessionId: sessionId,
      payload: new TextEncoder().encode(payload),
    }));

    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

    console.log(`--- Response (${elapsed}s) ---`);
    console.log(`  HTTP status:       ${response.$metadata.httpStatusCode}`);
    console.log(`  Request ID:        ${response.$metadata.requestId}`);
    console.log(`  Content type:      ${response.contentType}`);
    console.log(`  Runtime session:   ${response.runtimeSessionId}`);
    console.log(`  Status code:       ${response.statusCode}`);

    if (response.response) {
      const body = await response.response.transformToString();
      console.log('\n--- Agent response ---');
      try {
        console.log(JSON.stringify(JSON.parse(body), null, 2));
      } catch {
        console.log(body);
      }
    } else {
      console.log('\n  (No response body)');
    }

    console.log('\n=== SUCCESS ===');
  } catch (err: unknown) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    console.error(`--- Invocation FAILED (${elapsed}s) ---\n`);

    if (err instanceof Error) {
      console.error(`  Name:    ${err.name}`);
      console.error(`  Message: ${err.message}`);

      const sdkErr = err as unknown as Record<string, unknown>;
      if (sdkErr.$metadata) {
        const meta = sdkErr.$metadata as Record<string, unknown>;
        console.error(`  HTTP:    ${meta.httpStatusCode}`);
        console.error(`  Req ID:  ${meta.requestId}`);
      }
      if (sdkErr.$fault) {
        console.error(`  Fault:   ${sdkErr.$fault}`);
      }
    } else {
      console.error(`  Error: ${err}`);
    }

    console.error('\nNext steps:');
    console.error('  1. Check runtime CloudWatch logs for Python import/startup errors');
    console.error('  2. Verify the runtime status is ACTIVE in the AWS console');
    console.error('  3. Verify bedrock:InvokeModel is granted to the runtime execution role');
    console.error('  4. Confirm bedrock-agentcore package is in requirements.txt');
    console.error('  5. Confirm handler.py uses @app.entrypoint from BedrockAgentCoreApp');
    process.exit(1);
  }
}

main();
