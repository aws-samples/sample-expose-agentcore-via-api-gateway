/**
 * Thin proxy Lambda.
 *
 * Forwards authorized requests from API Gateway to AgentCore Runtime
 * (OAuth-inbound) using the user's JWT as the Bearer token. Lives inside
 * a private VPC so the InvokeAgentRuntime call exits through the
 * bedrock-agentcore VPC endpoint, populating `aws:SourceVpc` and
 * `aws:SourceVpce` in the request context for the Runtime's
 * resource-based policy.
 *
 * Why not the AWS SDK? The SDK signs requests with SigV4. AgentCore is
 * configured for OAuth inbound here, so we forward the user's JWT
 * directly via a raw HTTPS POST and let AgentCore Identity validate it.
 * Private DNS on the VPC endpoint resolves
 * `bedrock-agentcore.<region>.amazonaws.com` to the endpoint's private
 * IP from inside the VPC.
 *
 * The composite session ID computed by the Lambda Authorizer is sent as
 * the `X-Amzn-Bedrock-AgentCore-Runtime-Session-Id` header so AgentCore
 * Runtime sees a session ID cryptographically bound to the user.
 *
 * Streams the upstream response body back through API Gateway response
 * streaming for low time-to-first-byte.
 */

const AGENT_RUNTIME_ARN = process.env.AGENT_RUNTIME_ARN ?? '';
const REGION = process.env.AWS_REGION ?? '';

const NULL_DELIMITER = '\x00'.repeat(8);

declare const awslambda: {
  streamifyResponse: (
    handler: (event: any, responseStream: any, context: any) => Promise<void>,
  ) => any;
};

// AgentCore Runtime data plane URL.
// Format: https://bedrock-agentcore.<region>.amazonaws.com
//           /runtimes/<urlEncodedRuntimeArn>/invocations?qualifier=DEFAULT
function buildRuntimeUrl(runtimeArn: string, region: string): string {
  return (
    `https://bedrock-agentcore.${region}.amazonaws.com` +
    `/runtimes/${encodeURIComponent(runtimeArn)}` +
    `/invocations?qualifier=DEFAULT`
  );
}

function writePrelude(
  responseStream: any,
  statusCode: number,
  contentType = 'application/json',
): void {
  responseStream.write(JSON.stringify({ statusCode, headers: { 'Content-Type': contentType } }));
  responseStream.write(NULL_DELIMITER);
}

function writeError(
  responseStream: any,
  statusCode: number,
  code: string,
  message: string,
): void {
  writePrelude(responseStream, statusCode);
  responseStream.write(JSON.stringify({ success: false, error: { code, message } }));
  responseStream.end();
}

export const handler = awslambda.streamifyResponse(
  async (event: any, responseStream: any): Promise<void> => {
    try {
      const body = event.body ? JSON.parse(event.body) : {};
      const prompt: string | undefined = body.prompt;

      if (!prompt) {
        writeError(responseStream, 400, 'BAD_REQUEST', 'Missing prompt');
        return;
      }

      const compositeSessionId =
        event.requestContext?.authorizer?.compositeSessionId ?? '';
      if (!compositeSessionId) {
        writeError(
          responseStream,
          400,
          'BAD_REQUEST',
          'Missing composite session ID from authorizer',
        );
        return;
      }

      // Extract the user's JWT from the Authorization header. API Gateway
      // preserves header case in REST API REQUEST authorizer events but
      // normalizes elsewhere — check both spellings.
      const headers: Record<string, string> = event.headers ?? {};
      const auth = headers.Authorization ?? headers.authorization ?? '';
      if (!auth.startsWith('Bearer ')) {
        writeError(responseStream, 401, 'UNAUTHORIZED', 'Missing bearer token');
        return;
      }

      const url = buildRuntimeUrl(AGENT_RUNTIME_ARN, REGION);

      // Forward the user's JWT to AgentCore Identity. No SigV4 signing.
      // Inject the composite session ID so AgentCore Runtime treats this
      // user-bound hash as the session identifier.
      const upstream = await fetch(url, {
        method: 'POST',
        headers: {
          Authorization: auth,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'X-Amzn-Bedrock-AgentCore-Runtime-Session-Id': compositeSessionId,
        },
        body: JSON.stringify({ prompt }),
      });

      writePrelude(
        responseStream,
        upstream.status,
        upstream.headers.get('content-type') ?? 'application/json',
      );

      if (upstream.body) {
        const reader = upstream.body.getReader();
        try {
          for (;;) {
            const { value, done } = await reader.read();
            if (done) break;
            if (value) responseStream.write(Buffer.from(value));
          }
        } finally {
          reader.releaseLock();
        }
      }
      responseStream.end();
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      console.log(
        JSON.stringify({ error: message, timestamp: new Date().toISOString() }),
      );
      writeError(responseStream, 500, 'AGENT_ERROR', message);
    }
  },
);
