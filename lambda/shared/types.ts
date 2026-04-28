/**
 * Decoded JWT claims from a Cognito-issued ID token.
 * The `sub` field is the key identity claim used to derive the composite
 * session ID that is passed downstream to AgentCore Runtime.
 */
export interface JWTClaims {
  /** User identity — mixed into the composite session hash */
  sub: string;
  /** User email address */
  email: string;
  /** Optional Cognito group memberships */
  'cognito:groups'?: string[];
  /** Issued at — Unix epoch seconds */
  iat: number;
  /** Expiration — Unix epoch seconds */
  exp: number;
  /** Cognito issuer URL */
  iss: string;
  /** Client ID (audience) */
  aud: string;
  /** Token type — always 'id' for ID tokens */
  token_use: 'id';
}

/**
 * DynamoDB Throttle table record. The table uses synthetic prefixed partition
 * keys to track two counters:
 *   - `USER#<sub>`                      → per-user active session count
 *   - `INVOCATIONS#<compositeSessionId>` → per-session invocation count
 *
 * The table is not used for session binding or ownership — that is enforced
 * cryptographically by the composite hash in the authorizer.
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
 * Lambda Authorizer request event from API Gateway (REQUEST type).
 */
export interface AuthorizerEvent {
  /** Authorizer type — always 'REQUEST' for request-based authorizers */
  type: 'REQUEST';
  /** API Gateway method ARN used to generate the IAM policy */
  methodArn: string;
  /** HTTP headers from the client request */
  headers: Record<string, string>;
  /** Request context including client identity */
  requestContext: {
    identity: { sourceIp: string };
  };
}

/**
 * Lambda Authorizer response returned to API Gateway.
 * Contains an IAM policy document and optional context passed to downstream Lambdas.
 */
export interface AuthorizerResponse {
  /** The principal identifier for the policy */
  principalId: string;
  /** IAM policy document with a single Allow or Deny statement */
  policyDocument: {
    Version: '2012-10-17';
    Statement: [{
      Action: 'execute-api:Invoke';
      Effect: 'Allow' | 'Deny';
      Resource: string;
    }];
  };
  /** Context values passed to downstream Lambda functions */
  context: {
    userId: string;
    sessionId: string;
    compositeSessionId: string;
  };
}
