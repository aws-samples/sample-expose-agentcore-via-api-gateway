/**
 * Thin proxy Lambda — streams authorized requests from AgentCore Runtime
 * back to the client via API Gateway response streaming.
 *
 * Uses awslambda.streamifyResponse so API Gateway can progressively send
 * response bytes as they arrive from AgentCore, reducing time-to-first-byte.
 */

import {
  BedrockAgentCoreClient,
  InvokeAgentRuntimeCommand,
} from '@aws-sdk/client-bedrock-agentcore';

const AGENT_RUNTIME_ARN = process.env.AGENT_RUNTIME_ARN ?? '';
const agentCoreClient = new BedrockAgentCoreClient({});

const NULL_DELIMITER = '\x00'.repeat(8);

declare const awslambda: {
  streamifyResponse: (
    handler: (event: any, responseStream: any, context: any) => Promise<void>,
  ) => any;
};

export const handler = awslambda.streamifyResponse(
  async (event: any, responseStream: any): Promise<void> => {
    try {
      const body = event.body ? JSON.parse(event.body) : {};
      const prompt: string | undefined = body.prompt;

      if (!prompt) {
        responseStream.write('{"statusCode": 400}');
        responseStream.write(NULL_DELIMITER);
        responseStream.write(JSON.stringify({ success: false, error: { code: 'BAD_REQUEST', message: 'Missing prompt' } }));
        responseStream.end();
        return;
      }

      const compositeSessionId = event.requestContext?.authorizer?.compositeSessionId ?? '';
      if (!compositeSessionId) {
        responseStream.write('{"statusCode": 400}');
        responseStream.write(NULL_DELIMITER);
        responseStream.write(JSON.stringify({ success: false, error: { code: 'BAD_REQUEST', message: 'Missing composite session ID from authorizer' } }));
        responseStream.end();
        return;
      }

      const response = await agentCoreClient.send(new InvokeAgentRuntimeCommand({
        agentRuntimeArn: AGENT_RUNTIME_ARN,
        contentType: 'application/json',
        accept: 'application/json',
        runtimeSessionId: compositeSessionId,
        payload: new TextEncoder().encode(JSON.stringify({ prompt })),
      }));

      responseStream.write(JSON.stringify({ statusCode: 200, headers: { 'Content-Type': 'text/event-stream; charset=utf-8' } }));
      responseStream.write(NULL_DELIMITER);

      if (response.response) {
        const sdkStream = response.response as any;
        await new Promise<void>((resolve, reject) => {
          sdkStream.on('data', (chunk: Buffer | Uint8Array) => {
            responseStream.write(chunk);
          });
          sdkStream.on('end', () => {
            responseStream.end();
            resolve();
          });
          sdkStream.on('error', (err: Error) => {
            responseStream.end();
            reject(err);
          });
        });
      } else {
        responseStream.end();
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      console.log(JSON.stringify({ error: message, timestamp: new Date().toISOString() }));
      responseStream.write('{"statusCode": 500}');
      responseStream.write(NULL_DELIMITER);
      responseStream.write(JSON.stringify({ success: false, error: { code: 'AGENT_ERROR', message } }));
      responseStream.end();
    }
  },
);
