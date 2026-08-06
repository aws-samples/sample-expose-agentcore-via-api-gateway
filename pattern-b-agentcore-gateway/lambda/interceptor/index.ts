// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * AgentCore Gateway REQUEST interceptor — JWT validation, composite session
 * hashing, per-user / per-session throttling, and structured audit logging.
 *
 * This is the customer-side authorization brain that used to live in the API
 * Gateway Lambda Authorizer. It now runs as a Gateway REQUEST interceptor in
 * front of an AgentCore Runtime (HTTP) target:
 *
 *   Client → AgentCore Gateway (CUSTOM_JWT inbound) → THIS interceptor
 *          → AgentCore Runtime (OAuth inbound; Gateway uses OAUTH client-
 *            credentials outbound so the runtime's allowedWorkloadConfiguration
 *            is satisfied)
 *
 * Security model:
 *   - JWT is validated here (signature, issuer, expiry). The Gateway's
 *     CUSTOM_JWT inbound is the first gate; re-validating here lets us emit
 *     INVALID_JWT telemetry, read `sub` for the composite hash, and forward a
 *     TRUSTED user identity to the agent.
 *   - The runtime session ID is a composite hash sha256(<X-Session-Id>:<sub>),
 *     never the raw client value, injected as
 *     X-Amzn-Bedrock-AgentCore-Runtime-Session-Id.
 *   - Because the Gateway's OAuth outbound replaces Authorization with its M2M
 *     token, the user identity is propagated to the agent via interceptor-set
 *     verified headers (X-Verified-User-Sub, X-User-Authorization) — set only
 *     after JWT validation, with any client-supplied variants stripped.
 *   - Per-user session and per-session invocation limits via DynamoDB
 *     conditional writes.
 *
 * FAIL-SECURE: every rejection path — and any unexpected error — returns a
 * `transformedGatewayResponse` (a short-circuit deny). The gateway returns
 * that response immediately WITHOUT calling the Runtime target. The handler
 * never throws: a thrown exception could be retried or handled by the gateway
 * in an implementation-defined way, so we convert all errors into an explicit
 * deny here.
 */

import { createHash } from 'crypto';
import * as jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand, UpdateCommand, PutCommand } from '@aws-sdk/lib-dynamodb';
import type {
  JWTClaims,
  InterceptorRequestEvent,
  InterceptorClientContext,
  InterceptorResponse,
} from '../shared/types';

// ---------------------------------------------------------------------------
// Config + clients (initialized once per cold start)
// ---------------------------------------------------------------------------

const THROTTLE_TABLE_NAME = process.env.THROTTLE_TABLE_NAME ?? '';
const COGNITO_ISSUER = process.env.COGNITO_ISSUER ?? '';
const MAX_SESSIONS = parseInt(process.env.MAX_SESSIONS_PER_USER ?? '5', 10);
const MAX_INVOCATIONS = parseInt(process.env.MAX_INVOCATIONS_PER_SESSION ?? '100', 10);
const SESSION_TTL_SECONDS = parseInt(process.env.SESSION_TTL_HOURS ?? '24', 10) * 3600;

/** Canonical header AgentCore Runtime reads for the session identifier. */
const RUNTIME_SESSION_HEADER = 'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id';

/**
 * Verified user-identity headers injected on allow. The Gateway's OAuth
 * outbound replaces Authorization with the M2M token, so the runtime no longer
 * sees the user's token. To preserve OBO we forward the user's identity — only
 * AFTER validating the JWT here — in these interceptor-controlled headers,
 * which the runtime allowlists through to the agent. Any client-supplied
 * variants are stripped so the agent can trust these values.
 */
const VERIFIED_USER_SUB_HEADER = 'X-Verified-User-Sub';
const VERIFIED_USER_TOKEN_HEADER = 'X-User-Authorization';

/** Interceptor-controlled headers stripped from the client-supplied set. */
const STRIPPED_CLIENT_HEADERS = [
  RUNTIME_SESSION_HEADER.toLowerCase(),
  VERIFIED_USER_SUB_HEADER.toLowerCase(),
  VERIFIED_USER_TOKEN_HEADER.toLowerCase(),
];

const ddbClient = DynamoDBDocumentClient.from(new DynamoDBClient({}));

const jwks = jwksClient({
  jwksUri: `${COGNITO_ISSUER}/.well-known/jwks.json`,
  cache: true,
  cacheMaxAge: 600_000, // 10 minutes
});

// ---------------------------------------------------------------------------
// JWT helpers
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

export function extractBearerToken(authHeader: string | undefined): string | undefined {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return undefined;
  }
  return authHeader.slice(7) || undefined;
}

export async function validateJWT(token: string, cognitoIssuer: string): Promise<JWTClaims> {
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
// Interceptor output builders
// ---------------------------------------------------------------------------

/** Build a fail-secure deny that short-circuits the gateway (target not called). */
export function deny(statusCode: number, code: string, message: string): InterceptorResponse {
  const body = Buffer.from(
    JSON.stringify({ success: false, error: { code, message } }),
  ).toString('base64');
  return {
    interceptorOutputVersion: '1.0',
    http: {
      transformedGatewayResponse: {
        statusCode,
        contentType: 'application/json',
        body,
      },
    },
  };
}

/**
 * Build an allow that forwards the request to the Runtime target.
 * Echoes the original headers, strips any interceptor-controlled header the
 * client tried to set, injects the user-bound composite session ID, and
 * injects the VERIFIED user identity (sub + original bearer token) for OBO.
 * The user token is forwarded here — after JWT validation — because the
 * Gateway's OAuth outbound overwrites Authorization with the M2M token.
 */
export function allow(
  originalHeaders: Record<string, string>,
  compositeSessionId: string,
  base64Body: string,
  verifiedSub: string,
  verifiedUserToken: string,
): InterceptorResponse {
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(originalHeaders)) {
    // Drop any case-variant of interceptor-controlled headers — we set them.
    if (STRIPPED_CLIENT_HEADERS.includes(key.toLowerCase())) {
      continue;
    }
    headers[key] = value;
  }
  headers[RUNTIME_SESSION_HEADER] = compositeSessionId;
  headers[VERIFIED_USER_SUB_HEADER] = verifiedSub;
  headers[VERIFIED_USER_TOKEN_HEADER] = `Bearer ${verifiedUserToken}`;
  return {
    interceptorOutputVersion: '1.0',
    http: { transformedGatewayRequest: { headers, body: base64Body } },
  };
}

// ---------------------------------------------------------------------------
// Structured JSON audit logging — one entry per invocation
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
  event: InterceptorRequestEvent,
  context?: { clientContext?: { Custom?: InterceptorClientContext } },
): Promise<InterceptorResponse> {
  const now = new Date().toISOString();
  const sourceIp = context?.clientContext?.Custom?.SOURCE_IP;

  try {
    const gatewayRequest = event?.http?.gatewayRequest;
    const rawHeaders = gatewayRequest?.headers ?? {};
    const base64Body = gatewayRequest?.body ?? '';

    // Normalize header keys to lowercase for case-insensitive lookup.
    const headers: Record<string, string> = {};
    for (const [key, value] of Object.entries(rawHeaders)) {
      headers[key.toLowerCase()] = value;
    }

    // Step 1: Extract JWT from Authorization header.
    const token = extractBearerToken(headers['authorization']);
    if (!token) {
      logAuthorization({ decision: 'Deny', reason: 'MISSING_TOKEN', timestamp: now, sourceIp });
      return deny(401, 'MISSING_TOKEN', 'Missing bearer token');
    }

    // Step 2: Validate JWT (signature, expiry, issuer). Defense in depth on
    // top of the Gateway CUSTOM_JWT inbound and the Runtime OAuth inbound.
    let claims: JWTClaims;
    try {
      claims = await validateJWT(token, COGNITO_ISSUER);
    } catch (jwtError: unknown) {
      const isExpired = jwtError instanceof jwt.TokenExpiredError;
      const reason = isExpired ? 'JWT_EXPIRED' : 'INVALID_JWT';
      logAuthorization({ decision: 'Deny', reason, timestamp: now, sourceIp });
      return deny(401, reason, 'Invalid or expired token');
    }

    // Step 3: Extract and validate the client session ID (X-Session-Id).
    const sessionId = headers['x-session-id'];
    if (!sessionId) {
      logAuthorization({ userId: claims.sub, decision: 'Deny', reason: 'MISSING_SESSION_ID', timestamp: now, sourceIp });
      return deny(400, 'MISSING_SESSION_ID', 'Missing X-Session-Id header');
    }

    // UUID v4 format (lowercase hex + hyphens, 36 chars). Also guarantees the
    // client value can never collide with synthetic throttle keys
    // (`USER#...`, `INVOCATIONS#...`).
    const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
    if (!UUID_REGEX.test(sessionId)) {
      logAuthorization({ userId: claims.sub, sessionId, decision: 'Deny', reason: 'INVALID_SESSION_ID_FORMAT', timestamp: now, sourceIp });
      return deny(403, 'INVALID_SESSION_ID_FORMAT', 'X-Session-Id must be a UUID v4');
    }

    // Step 4: Composite session ID — cryptographically binds session to user.
    // sha256(clientUuid:jwtSub) → 64-char hex. Two users sending the same UUID
    // get different composites, so they can never share a Runtime session.
    const compositeSessionId = createHash('sha256')
      .update(`${sessionId}:${claims.sub}`)
      .digest('hex');

    // Step 5: Throttling — per-user session + per-session invocation limits.
    const invocationKey = `INVOCATIONS#${compositeSessionId}`;
    const ttl = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;

    const invocationRecord = await ddbClient.send(new GetCommand({
      TableName: THROTTLE_TABLE_NAME,
      Key: { pk: invocationKey },
    }));

    if (!invocationRecord.Item) {
      // New session — enforce per-user session limit.
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
          logAuthorization({ userId: claims.sub, sessionId, decision: 'Deny', reason: 'SESSION_LIMIT_EXCEEDED', maxSessions: MAX_SESSIONS, timestamp: now, sourceIp });
          return deny(429, 'SESSION_LIMIT_EXCEEDED', 'Per-user session limit exceeded');
        }
        throw err;
      }

      // Create the invocation tracking record with counter = 1.
      await ddbClient.send(new PutCommand({
        TableName: THROTTLE_TABLE_NAME,
        Item: { pk: invocationKey, invocationCount: 1, userId: claims.sub, expiresAt: ttl },
      }));
    } else {
      // Existing session — enforce per-session invocation limit (atomic).
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
          logAuthorization({ userId: claims.sub, sessionId, decision: 'Deny', reason: 'INVOCATION_LIMIT_EXCEEDED', maxInvocations: MAX_INVOCATIONS, timestamp: now, sourceIp });
          return deny(429, 'INVOCATION_LIMIT_EXCEEDED', 'Per-session invocation limit exceeded');
        }
        throw err;
      }
    }

    // Step 6: All checks pass — forward with the injected composite session ID
    // and the verified user identity headers (sub + validated bearer token).
    logAuthorization({ userId: claims.sub, sessionId, compositeSessionId, decision: 'Allow', reason: 'AUTHORIZED', timestamp: now, sourceIp });
    return allow(rawHeaders, compositeSessionId, base64Body, claims.sub, token);
  } catch {
    // Catch-all: fail-secure on any unexpected error (never throw).
    logAuthorization({ decision: 'Deny', reason: 'INTERNAL_ERROR', timestamp: now, sourceIp });
    return deny(500, 'INTERNAL_ERROR', 'Authorization failed');
  }
}
