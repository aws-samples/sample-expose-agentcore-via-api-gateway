// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Decoded JWT claims from a Cognito-issued token.
 * The `sub` field is the key identity claim used to derive the composite
 * session ID that is passed downstream to AgentCore Runtime.
 */
export interface JWTClaims {
  /** User identity — mixed into the composite session hash */
  sub: string;
  /** User email address */
  email?: string;
  /** Optional Cognito group memberships */
  'cognito:groups'?: string[];
  /** Issued at — Unix epoch seconds */
  iat: number;
  /** Expiration — Unix epoch seconds */
  exp: number;
  /** Cognito issuer URL */
  iss: string;
  /** Audience (ID tokens) */
  aud?: string;
  /** Client ID (access tokens) */
  client_id?: string;
  /** Token type — 'id' or 'access' */
  token_use?: string;
}

/**
 * DynamoDB Throttle table record. The table uses synthetic prefixed partition
 * keys to track two counters:
 *   - `USER#<sub>`                      → per-user active session count
 *   - `INVOCATIONS#<compositeSessionId>` → per-session invocation count
 *
 * The table is not used for session binding or ownership — that is enforced
 * cryptographically by the composite hash in the interceptor.
 */
export interface ThrottleRecord {
  /** Partition key — `USER#<sub>` or `INVOCATIONS#<compositeSessionId>` */
  pk: string;
  /** Present on `USER#...` rows — active sessions this user has opened */
  sessionCount?: number;
  /** Present on `INVOCATIONS#...` rows — invocations made in this session */
  invocationCount?: number;
  /** JWT `sub` that opened the session (stored on INVOCATIONS rows for audit) */
  userId?: string;
  /** Unix epoch seconds — TTL attribute for automatic expiration */
  expiresAt: number;
}

/**
 * AgentCore Gateway REQUEST interceptor input for an HTTP (AgentCore Runtime)
 * target. See:
 * https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html
 *
 * `headers` is present only when the interceptor is configured with
 * `passRequestHeaders: true`. `body` is a base64-encoded string of the raw
 * HTTP request body. `httpMethod` is read-only.
 */
export interface InterceptorRequestEvent {
  interceptorInputVersion: string;
  http: {
    gatewayRequest: {
      path: string;
      httpMethod: string;
      /** Present only when passRequestHeaders=true */
      headers?: Record<string, string>;
      /** base64-encoded raw request body */
      body: string;
    };
  };
}

/**
 * Custom values the gateway passes to an HTTP-target interceptor via the
 * Lambda invocation client context (`clientContext.Custom`).
 * `GATEWAY_ARN`, `GATEWAY_ACCOUNT_ID`, and `REQUEST_ID` are always present;
 * `SOURCE_IP` is optional.
 */
export interface InterceptorClientContext {
  GATEWAY_ARN?: string;
  GATEWAY_ACCOUNT_ID?: string;
  REQUEST_ID?: string;
  SOURCE_IP?: string;
}

/**
 * Allow output — forward a (possibly header-modified) request to the target.
 * We echo the original headers plus the injected composite session-ID header,
 * and echo the original base64 body unchanged.
 */
export interface InterceptorAllowResponse {
  interceptorOutputVersion: '1.0';
  http: {
    transformedGatewayRequest: {
      headers: Record<string, string>;
      /** base64-encoded body, unchanged */
      body: string;
    };
  };
}

/**
 * Deny output (fail-secure short-circuit). When `transformedGatewayResponse`
 * is present the gateway returns it immediately WITHOUT calling the target.
 * `body` must be base64-encoded.
 */
export interface InterceptorDenyResponse {
  interceptorOutputVersion: '1.0';
  http: {
    transformedGatewayResponse: {
      statusCode: number;
      contentType: string;
      headers?: Record<string, string>;
      /** base64-encoded body */
      body: string;
    };
  };
}

export type InterceptorResponse =
  | InterceptorAllowResponse
  | InterceptorDenyResponse;
