#!/usr/bin/env ts-node
/**
 * Seed Cognito test users for the security sample.
 *
 * The authorizer no longer reads a DynamoDB session-binding record — session
 * isolation is enforced cryptographically via the composite session ID
 * (sha256(uuid:jwtSub)). Clients may generate any UUID v4 they like per
 * session; the authorizer will derive a user-scoped AgentCore session from it.
 *
 * This script only provisions the two test users and emits a pair of UUIDs
 * for the end-to-end security test script to reuse.
 *
 * Usage:
 *   export AWS_REGION=<from CDK output>
 *   export USER_POOL_ID=<from CDK output>
 *   npx ts-node scripts/seed-data.ts
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  CognitoIdentityProviderClient,
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  AdminGetUserCommand,
} from '@aws-sdk/client-cognito-identity-provider';

const REGION = process.env.AWS_REGION ?? 'us-east-1';
const USER_POOL_ID = process.env.USER_POOL_ID ?? '';
const SEED_OUTPUT_PATH = path.join(__dirname, 'seed-output.json');

const cognito = new CognitoIdentityProviderClient({ region: REGION });

function generatePassword(): string {
  const base = crypto.randomBytes(16).toString('base64');
  // Ensure the password meets Cognito's strict policy (upper, lower, digit, symbol)
  return base + 'Aa1!';
}

const TEST_USERS = [
  { username: 'user1@test.com', password: generatePassword() },
  { username: 'user2@test.com', password: generatePassword() },
];

async function ensureUser(email: string, password: string): Promise<string> {
  let userExists = false;
  try {
    await cognito.send(
      new AdminGetUserCommand({ UserPoolId: USER_POOL_ID, Username: email }),
    );
    userExists = true;
  } catch {
    // User doesn't exist — create below
  }

  if (!userExists) {
    await cognito.send(
      new AdminCreateUserCommand({
        UserPoolId: USER_POOL_ID,
        Username: email,
        UserAttributes: [
          { Name: 'email', Value: email },
          { Name: 'email_verified', Value: 'true' },
        ],
        MessageAction: 'SUPPRESS',
      }),
    );
  }

  // Always set the password so it matches the freshly generated value written
  // to seed-output.json. Without this, re-running the seed against an existing
  // user pool leaves the old password in Cognito and auth fails.
  await cognito.send(
    new AdminSetUserPasswordCommand({
      UserPoolId: USER_POOL_ID,
      Username: email,
      Password: password,
      Permanent: true,
    }),
  );

  const user = await cognito.send(
    new AdminGetUserCommand({ UserPoolId: USER_POOL_ID, Username: email }),
  );
  const sub = user.UserAttributes?.find((a) => a.Name === 'sub')?.Value ?? '';
  console.log(`  ${userExists ? 'Updated' : 'Created'} user ${email} (sub: ${sub})`);
  return sub;
}

interface SeedOutput {
  user1Sub: string;
  user2Sub: string;
  user1SessionId: string;
  user2SessionId: string;
  user1Password: string;
  user2Password: string;
}

async function main(): Promise<void> {
  console.log('\n=== AgentCore Runtime Security Sample — Seed Data ===\n');

  if (!USER_POOL_ID) {
    console.error('ERROR: USER_POOL_ID environment variable is required.');
    console.error('Run scripts/deploy.sh first and export the stack outputs.');
    process.exit(1);
  }

  console.log('1. Creating/verifying Cognito test users...');
  const user1Sub = await ensureUser(TEST_USERS[0].username, TEST_USERS[0].password);
  const user2Sub = await ensureUser(TEST_USERS[1].username, TEST_USERS[1].password);

  const output: SeedOutput = {
    user1Sub,
    user2Sub,
    user1SessionId: crypto.randomUUID(),
    user2SessionId: crypto.randomUUID(),
    user1Password: TEST_USERS[0].password,
    user2Password: TEST_USERS[1].password,
  };

  fs.writeFileSync(SEED_OUTPUT_PATH, JSON.stringify(output, null, 2) + '\n');
  console.log(`\n  Wrote seed output to ${SEED_OUTPUT_PATH}`);

  console.log('\n=== Seed complete ===');
  console.log(`  User 1: ${TEST_USERS[0].username} (sub: ${user1Sub})`);
  console.log(`  User 2: ${TEST_USERS[1].username} (sub: ${user2Sub})`);
  console.log(`  Passwords and session UUIDs written to ${SEED_OUTPUT_PATH}`);
  console.log(`  (file is gitignored — do not commit it)`);
}

main().catch((err) => {
  console.error('Seed failed:', err);
  process.exit(1);
});
