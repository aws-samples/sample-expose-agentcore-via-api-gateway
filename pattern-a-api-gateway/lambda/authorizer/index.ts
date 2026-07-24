/**
 * Lambda Authorizer — JWT validation, composite session hashing, and throttling.
 *
 * Validates Cognito-issued JWTs, derives a composite session ID that is
 * cryptographically bound to the authenticated user (sha256(uuid:jwtSub)),
 * and applies per-user session limits and per-session invocation throttling
 * using DynamoDB atomic counters.
 *
 * Session hijacking is prevented by the composite hash itself: two users
 * submitting the same client UUID produce different composite IDs, so they
 * cannot land on the same AgentCore Runtime session. DynamoDB is used only
 * to store throttle counters.
 *
 * All error paths return Deny (fail-secure).
 */

import { createHash } from 'crypto';
import * as jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import type {
  AuthorizerEvent,
  AuthorizerResponse,
  JWTClaims,
} from '../shared/types';

// ---------------------------------------------------------------------------
// Clients (initialized once per cold start)
// ---------------------------------------------------------------------------

const THROTTLE_TABLE_NAME = process.env.THROTTLE_TABLE_NAME ?? '';
const COGNITO_ISSUER = process.env.COGNITO_ISSUER ?? '';
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS_PER_USER ?? '5', 10);
const MAX_INVOCATIONS = parseInt(process.env.MAX_INVOCATIONS_PER_SESSION ?? '100', 10);
const SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL_HOURS ?? '24', 10) * 3600;

const ddbClient = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const jwks = jwksClient({
  jwksUri: `${COGNITO_ISSUER}/.well-known/jwks.json`,
  cache: true,
  cacheMaxAge: 600_000, // 10 minutes
});

// ---------------------------------------------------------------------------
// Helper: signing key callback for jsonwebtoken
// ---------------------------------------------------------------------------

function getSigningKey(header: jwt.JwtHeader, callback: jwt.SigningKeyCallback): void {
  if (!header.kid) {
    callback(new Error('JWT header missing kid'));
    return;
  }
  jwks.getSigningKey(header.kid, (err, key) => {
    if (err || !key) {
      callback(err ?? new Error('Signing key not found'));
      return;
    }
    callback(null, key.getPublicKey());
  });
}

// ---------------------------------------------------------------------------
// extractBearerToken — parses "Bearer <token>" from Authorization header
// ---------------------------------------------------------------------------

export function extractBearerToken(authHeader: string | undefined): string | undefined {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return undefined;
  }
  return authHeader.slice(7) || undefined;
}

// ---------------------------------------------------------------------------
// validateJWT — verify Cognito-issued token
// ---------------------------------------------------------------------------

export async function validateJWT(
  token: string,
  cognitoIssuer: string,
): Promise<JWTClaims> {
  return new Promise<JWTClaims>((resolve, reject) => {
    jwt.verify(
      token,
      getSigningKey,
      { issuer: cognitoIssuer, algorithms: ['RS256'] },
      (err, decoded) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(decoded as JWTClaims);
      },
    );
  });
}

// ---------------------------------------------------------------------------
// generatePolicy — build Allow / Deny IAM policy document
// ---------------------------------------------------------------------------

export function generatePolicy(
  principalId: string,
  effect: 'Allow' | 'Deny',
  resource: string,
  context: AuthorizerResponse['context'] = {
    userId: '',
    sessionId: '',
    compositeSessionId: '',
  },
): AuthorizerResponse {
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: effect,
          Resource: resource,
        },
      ],
    },
    context,
  };
}

// ---------------------------------------------------------------------------
// Structured JSON logging — one entry per invocation
// ---------------------------------------------------------------------------

interface AuditEntry {
  userId?: string;
  sessionId?: string;
  decision: 'Allow' | 'Deny';
  reason: string;
  timestamp: string;
  [key: string]: unknown;
}

function logAuthorization(entry: AuditEntry): void {
  console.log(JSON.stringify(entry));
}

// ---------------------------------------------------------------------------
// Lambda handler
// ---------------------------------------------------------------------------

export async function handler(
  event: AuthorizerEvent,
): Promise<AuthorizerResponse> {
  const methodArn = event.methodArn;
  const now = new Date().toISOString();

  // Normalize headers to lowercase keys (API GW REQUEST authorizer preserves original casing)
  const headers: Record<string, string> = {};
  if (event.headers) {
    for (const [key, value] of Object.entries(event.headers)) {
      headers[key.toLowerCase()] = value;
    }
  }

  try {
    // Step 1: Extract JWT from Authorization header
    const token = extractBearerToken(headers['authorization']);
    if (!token) {
      logAuthorization({
        decision: 'Deny',
        reason: 'MISSING_TOKEN',
        timestamp: now,
      });
      return generatePolicy('anonymous', 'Deny', methodArn);
    }

    // Step 2: Validate JWT (signature, expiry, issuer)
    let claims: JWTClaims;
    try {
      claims = await validateJWT(token, COGNITO_ISSUER);
    } catch (jwtError: unknown) {
      const isExpired = jwtError instanceof jwt.TokenExpiredError;
      const reason = isExpired ? 'JWT_EXPIRED' : 'INVALID_JWT';
      logAuthorization({
        decision: 'Deny',
        reason,
        timestamp: now,
      });
      return generatePolicy('anonymous', 'Deny', methodArn);
    }

    // Step 3: Extract and validate session ID from x-session-id header
    const sessionId = headers['x-session-id'];
    if (!sessionId) {
      logAuthorization({
        userId: claims.sub,
        decision: 'Deny',
        reason: 'MISSING_SESSION_ID',
        timestamp: now,
      });
      return generatePolicy(claims.sub, 'Deny', methodArn);
    }

    // Validate UUID v4 format (lowercase hex + hyphens, 36 chars). The regex
    // also guarantees the client UUID can never collide with the synthetic
    // throttle-record keys (`USER#...`, `INVOCATIONS#...`).
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    if (!UUID_REGEX.test(sessionId)) {
      logAuthorization({
        userId: claims.sub,
        sessionId,
        decision: 'Deny',
        reason: 'INVALID_SESSION_ID_FORMAT',
        timestamp: now,
      });
      return generatePolicy(claims.sub, 'Deny', methodArn);
    }

    // Step 4: Build composite session ID — cryptographically binds session to user.
    // sha256(clientUuid:jwtSub) → 64-char hex, satisfies AgentCore ≥33 char minimum.
    // If two users send the same UUID, their composite IDs differ, so they can
    // never share an AgentCore Runtime session.
    const compositeSessionId = createHash('sha256')
      .update(`${sessionId}:${claims.sub}`)
      .digest('hex');

    // Step 5: Throttling — per-user session limit + per-session invocation limit.
    // Uses synthetic prefixed keys in the throttle table:
    //   INVOCATIONS#<compositeSessionId> — tracks invocation count per session
    //   USER#<sub>                       — tracks active session count per user
    const invocationKey = `INVOCATIONS#${compositeSessionId}`;
    const ttl = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;

    const invocationRecord = await ddbClient.send(new GetCommand({
      TableName: THROTTLE_TABLE_NAME,
      Key: { pk: invocationKey },
    }));

    if (!invocationRecord.Item) {
      // New session — enforce per-user session limit
      const userKey = `USER#${claims.sub}`;
      try {
        await ddbClient.send(new UpdateCommand({
          TableName: THROTTLE_TABLE_NAME,
          Key: { pk: userKey },
          UpdateExpression: 'SET sessionCount = if_not_exists(sessionCount, :zero) + :inc, expiresAt = :ttl',
          ConditionExpression: 'attribute_not_exists(sessionCount) OR sessionCount < :max',
          ExpressionAttributeValues: { ':zero': 0, ':inc': 1, ':max': MAX_SESSIONS, ':ttl': ttl },
        }));
      } catch (err: unknown) {
        if ((err as { name?: string }).name === 'ConditionalCheckFailedException') {
          logAuthorization({
            userId: claims.sub,
            sessionId,
            decision: 'Deny',
            reason: 'SESSION_LIMIT_EXCEEDED',
            maxSessions: MAX_SESSIONS,
            timestamp: now,
          });
          return generatePolicy(claims.sub, 'Deny', methodArn);
        }
        throw err;
      }

      // Create invocation tracking record with counter = 1
      await ddbClient.send(new PutCommand({
        TableName: THROTTLE_TABLE_NAME,
        Item: {
          pk: invocationKey,
          invocationCount: 1,
          userId: claims.sub,
          expiresAt: ttl,
        },
      }));
    } else {
      // Existing session — enforce per-session invocation limit (atomic increment)
      try {
        await ddbClient.send(new UpdateCommand({
          TableName: THROTTLE_TABLE_NAME,
          Key: { pk: invocationKey },
          UpdateExpression: 'SET invocationCount = invocationCount + :inc',
          ConditionExpression: 'invocationCount < :max',
          ExpressionAttributeValues: { ':inc': 1, ':max': MAX_INVOCATIONS },
        }));
      } catch (err: unknown) {
        if ((err as { name?: string }).name === 'ConditionalCheckFailedException') {
          logAuthorization({
            userId: claims.sub,
            sessionId,
            decision: 'Deny',
            reason: 'INVOCATION_LIMIT_EXCEEDED',
            maxInvocations: MAX_INVOCATIONS,
            timestamp: now,
          });
          return generatePolicy(claims.sub, 'Deny', methodArn);
        }
        throw err;
      }
    }

    // Step 6: All checks pass — Allow with context
    logAuthorization({
      userId: claims.sub,
      sessionId,
      compositeSessionId,
      decision: 'Allow',
      reason: 'AUTHORIZED',
      timestamp: now,
    });
    return generatePolicy(claims.sub, 'Allow', methodArn, {
      userId: claims.sub,
      sessionId,
      compositeSessionId,
    });
  } catch {
    // Catch-all: fail-secure on any unexpected error
    logAuthorization({
      decision: 'Deny',
      reason: 'INTERNAL_ERROR',
      timestamp: now,
    });
    return generatePolicy('anonymous', 'Deny', methodArn);
  }
}
