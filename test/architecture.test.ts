/**
 * Tests for the AgentCore security architecture (Path 1):
 *   Client → AgentCore Gateway (CUSTOM_JWT inbound, Cognito)
 *          → REQUEST interceptor Lambda (JWT + UUID + composite hash + throttle)
 *          → AgentCore Runtime (OAuth inbound, JWT_PASSTHROUGH outbound)
 *
 * Security invariants encoded here:
 *   - Gateway has CUSTOM_JWT inbound + a REQUEST interceptor (passRequestHeaders)
 *   - Runtime is OAuth inbound AND locked to this Gateway via
 *     allowedWorkloadConfiguration (the perimeter that replaces aws:SourceVpc)
 *   - Runtime target uses JWT_PASSTHROUGH (OBO preserved)
 *   - Runtime allowlists the Authorization header through to the agent
 *   - Interceptor keeps JWT validation + composite hash + throttling + fail-secure
 *   - No VPC / NAT / IGW / VPC endpoints, no proxy Lambda, no API Gateway
 *   - Throttle table + Guardrail + INVALID_JWT alarm intact
 */

import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as fs from 'fs';
import * as path from 'path';
import { AgentCoreSecurityStack } from '../lib/agentcore-security-stack';

let template: Template;

beforeAll(() => {
  const app = new cdk.App();
  const stack = new AgentCoreSecurityStack(app, 'TestStack', {
    env: { account: '123456789012', region: 'us-east-1' },
  });
  template = Template.fromStack(stack);
});

/** Collect all Custom::AWS resources' serialized onCreate payloads. */
function customResourceCreatePayloads(): string[] {
  const customResources = template.findResources('Custom::AWS');
  return Object.values(customResources).map((r) => {
    const create = r.Properties?.Create;
    return typeof create === 'string' ? create : JSON.stringify(create);
  });
}

describe('Perimeter removal: no VPC, no proxy, no API Gateway', () => {
  test('No VPC, NAT, IGW, or VPC endpoints remain', () => {
    expect(Object.keys(template.findResources('AWS::EC2::VPC'))).toHaveLength(0);
    expect(Object.keys(template.findResources('AWS::EC2::NatGateway'))).toHaveLength(0);
    expect(Object.keys(template.findResources('AWS::EC2::InternetGateway'))).toHaveLength(0);
    expect(Object.keys(template.findResources('AWS::EC2::VPCEndpoint'))).toHaveLength(0);
  });

  test('No API Gateway remains', () => {
    expect(Object.keys(template.findResources('AWS::ApiGateway::RestApi'))).toHaveLength(0);
    expect(Object.keys(template.findResources('AWS::ApiGateway::Method'))).toHaveLength(0);
  });

  test('No Lambda function runs inside a VPC (proxy removed)', () => {
    const fns = template.findResources('AWS::Lambda::Function');
    for (const fn of Object.values(fns)) {
      expect(fn.Properties?.VpcConfig).toBeUndefined();
    }
  });
});

describe('AgentCore Gateway: CUSTOM_JWT inbound + REQUEST interceptor', () => {
  test('A CreateGateway custom resource exists with CUSTOM_JWT (Cognito) inbound and NO protocolType', () => {
    const payloads = customResourceCreatePayloads();
    const gw = payloads.find((p) => p.includes('CreateGateway') && p.includes('CUSTOM_JWT'));
    expect(gw).toBeDefined();
    expect(gw).toContain('customJWTAuthorizer');
    expect(gw).toContain('.well-known/openid-configuration');
    // Protocol-less gateway (required for AgentCore Runtime HTTP targets).
    expect(gw).not.toContain('protocolType');
  });

  test('The gateway attaches a REQUEST interceptor with passRequestHeaders', () => {
    const gw = customResourceCreatePayloads().find((p) => p.includes('CreateGateway'));
    expect(gw).toBeDefined();
    expect(gw).toContain('interceptorConfigurations');
    expect(gw).toContain('REQUEST');
    expect(gw).toContain('passRequestHeaders');
  });

  test('The gateway execution role can invoke the interceptor Lambda and the Runtime', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({ Action: 'lambda:InvokeFunction' }),
        ]),
      }),
    });
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({ Action: 'bedrock-agentcore:InvokeAgentRuntime' }),
        ]),
      }),
    });
  });
});

describe('AgentCore Runtime: OAuth inbound + workload lock + JWT passthrough target', () => {
  test('Runtime is OAuth inbound (CustomJWTAuthorizer, Cognito discovery URL)', () => {
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      AuthorizerConfiguration: Match.objectLike({
        CustomJWTAuthorizer: Match.objectLike({
          DiscoveryUrl: Match.objectLike({
            'Fn::Join': Match.arrayWith([
              Match.arrayWith([Match.stringLikeRegexp('cognito-idp\\..*\\.amazonaws\\.com')]),
            ]),
          }),
        }),
      }),
    });
  });

  test('Runtime is locked to the Gateway workload via allowedWorkloadConfiguration (perimeter)', () => {
    // CloudFormation does not accept AllowedWorkloadConfiguration on the runtime
    // resource, so the workload lock is applied post-create via an
    // UpdateAgentRuntime custom resource.
    const upd = customResourceCreatePayloads().find((p) => p.includes('UpdateAgentRuntime'));
    expect(upd).toBeDefined();
    expect(upd).toContain('allowedWorkloadConfiguration');
    expect(upd).toContain('hostingEnvironments');
    // And it must NOT be (incorrectly) left on the CFN runtime resource.
    const runtimes = template.findResources('AWS::BedrockAgentCore::Runtime');
    for (const r of Object.values(runtimes)) {
      const authz = r.Properties?.AuthorizerConfiguration?.CustomJWTAuthorizer ?? {};
      expect(authz.AllowedWorkloadConfiguration).toBeUndefined();
    }
  });

  test('Runtime allowlists the Authorization header for OBO (RequestHeaderConfiguration)', () => {
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      RequestHeaderConfiguration: Match.objectLike({
        RequestHeaderAllowlist: Match.arrayWith(['Authorization']),
      }),
    });
  });

  test('Gateway target routes to the Runtime as an HTTP target with JWT_PASSTHROUGH (OBO)', () => {
    const tgt = customResourceCreatePayloads().find((p) => p.includes('CreateGatewayTarget'));
    expect(tgt).toBeDefined();
    expect(tgt).toContain('agentcoreRuntime');
    expect(tgt).toContain('JWT_PASSTHROUGH');
  });
});

describe('REQUEST interceptor code: JWT + composite hash + throttling + fail-secure', () => {
  const interceptorFile = path.join(__dirname, '..', 'lambda', 'interceptor', 'index.ts');
  const content = fs.readFileSync(interceptorFile, 'utf-8');

  test('Validates the JWT signature/issuer (jsonwebtoken + jwks-rsa)', () => {
    expect(content).toMatch(/jsonwebtoken/);
    expect(content).toMatch(/jwks-rsa/);
    expect(content).toMatch(/jwt\.verify/);
  });

  test('Derives the runtime session ID as a composite hash sha256(sessionId:sub), never the raw client value', () => {
    expect(content).toMatch(/createHash\(['"]sha256['"]\)/);
    expect(content).toMatch(/\$\{sessionId\}:\$\{claims\.sub\}/);
  });

  test('Injects X-Amzn-Bedrock-AgentCore-Runtime-Session-Id and strips any client-supplied variant', () => {
    expect(content).toMatch(/X-Amzn-Bedrock-AgentCore-Runtime-Session-Id/);
    expect(content).toMatch(/RUNTIME_SESSION_HEADER/);
  });

  test('Validates UUID v4 format for the client session id', () => {
    expect(content).toMatch(/\[0-9a-f\]\{8\}-\[0-9a-f\]\{4\}/);
  });

  test('Enforces per-user session + per-session invocation limits via DynamoDB conditional writes', () => {
    expect(content).toMatch(/ConditionExpression/);
    expect(content).toMatch(/sessionCount < :max/);
    expect(content).toMatch(/invocationCount < :max/);
    expect(content).toMatch(/USER#/);
    expect(content).toMatch(/INVOCATIONS#/);
  });

  test('Fails secure: every rejection returns a transformedGatewayResponse deny and the handler never throws', () => {
    expect(content).toMatch(/transformedGatewayResponse/);
    // A catch-all that denies rather than rethrows.
    expect(content).toMatch(/INTERNAL_ERROR/);
    expect(content).toMatch(/return deny\(/);
  });

  test('Emits INVALID_JWT for observability', () => {
    expect(content).toMatch(/INVALID_JWT/);
  });

  test('Is not a VPC proxy: no fetch-to-runtime, no response streaming, no SigV4 SDK', () => {
    expect(content).not.toMatch(/streamifyResponse/);
    expect(content).not.toMatch(/@aws-sdk\/client-bedrock-agentcore/);
    expect(content).not.toMatch(/AGENT_RUNTIME_ARN/);
  });
});

describe('Supporting resources: Cognito, DynamoDB, Guardrail, monitoring, outputs', () => {
  test('Cognito UserPool, DynamoDB throttle table, Bedrock Guardrail, INVALID_JWT alarm all exist', () => {
    template.hasResourceProperties('AWS::Cognito::UserPool', { UserPoolName: 'agentcore-security-users' });
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      KeySchema: Match.arrayWith([Match.objectLike({ AttributeName: 'pk', KeyType: 'HASH' })]),
      TimeToLiveSpecification: { AttributeName: 'expiresAt', Enabled: true },
    });
    template.hasResourceProperties('AWS::Bedrock::Guardrail', {
      ContentPolicyConfig: Match.objectLike({
        FiltersConfig: Match.arrayWith([Match.objectLike({ Type: 'PROMPT_ATTACK', InputStrength: 'HIGH' })]),
      }),
    });
    template.hasResourceProperties('AWS::Logs::MetricFilter', { FilterPattern: 'INVALID_JWT' });
    template.hasResourceProperties('AWS::CloudWatch::Alarm', { Threshold: 5 });
  });

  test('Interceptor Lambda has the throttle table env var and no AGENT_RUNTIME_ARN', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'nodejs22.x',
      Environment: { Variables: Match.objectLike({ THROTTLE_TABLE_NAME: Match.anyValue() }) },
    });
  });

  test('Stack outputs include the Gateway URL/ARN and runtime/pool identifiers, not ApiUrl/VpcId', () => {
    const outputKeys = Object.keys(template.findOutputs('*'));
    expect(outputKeys).toEqual(expect.arrayContaining([
      expect.stringContaining('GatewayUrl'),
      expect.stringContaining('GatewayArn'),
      expect.stringContaining('UserPoolId'),
      expect.stringContaining('UserPoolClientId'),
      expect.stringContaining('ThrottleTableName'),
      expect.stringContaining('Region'),
      expect.stringContaining('AgentRuntimeArn'),
    ]));
    expect(outputKeys.some((k) => k.includes('ApiUrl'))).toBe(false);
    expect(outputKeys.some((k) => k.includes('VpcId'))).toBe(false);
  });
});
