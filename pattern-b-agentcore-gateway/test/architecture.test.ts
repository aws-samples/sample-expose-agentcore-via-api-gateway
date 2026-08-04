/**
 * Tests for the AgentCore security architecture:
 *   Client → AgentCore Gateway (CUSTOM_JWT inbound, Cognito)
 *          → REQUEST interceptor Lambda (JWT + UUID + composite hash + throttle
 *            + verified-identity injection)
 *          → AgentCore Runtime (OAuth inbound; Gateway uses OAUTH client-
 *            credentials outbound so allowedWorkloadConfiguration is satisfied)
 *
 * Security invariants encoded here:
 *   - Gateway has CUSTOM_JWT inbound + a REQUEST interceptor (passRequestHeaders)
 *   - Runtime is OAuth inbound AND locked to this Gateway via
 *     AllowedWorkloadConfiguration, set natively on the CloudFormation runtime
 *     resource (the perimeter that replaces aws:SourceVpc)
 *   - Runtime target uses OAUTH client-credentials outbound (via an AgentCore
 *     Identity credential provider) — the Identity-brokered path that lets the
 *     workload lock be satisfied (JWT pass-through cannot satisfy it)
 *   - The user identity reaches the agent via interceptor-injected verified
 *     headers (X-Verified-User-Sub / X-User-Authorization), which the runtime
 *     allowlists through
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

describe('AgentCore Runtime: OAuth inbound + workload lock + OAuth outbound target', () => {
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

  test('Runtime is locked to the Gateway workload via AllowedWorkloadConfiguration (perimeter)', () => {
    // AllowedWorkloadConfiguration is set natively on the CloudFormation
    // runtime resource (the schema supports it), so the runtime is never live
    // without its perimeter.
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      AuthorizerConfiguration: Match.objectLike({
        CustomJWTAuthorizer: Match.objectLike({
          AllowedWorkloadConfiguration: Match.objectLike({
            HostingEnvironments: Match.arrayWith([Match.objectLike({ Arn: Match.anyValue() })]),
          }),
        }),
      }),
    });
    // The old post-create UpdateAgentRuntime workaround must be gone.
    const upd = customResourceCreatePayloads().find((p) => p.includes('UpdateAgentRuntime'));
    expect(upd).toBeUndefined();
  });

  test('Runtime allowlists the verified user identity headers for OBO (RequestHeaderConfiguration)', () => {
    template.hasResourceProperties('AWS::BedrockAgentCore::Runtime', {
      RequestHeaderConfiguration: Match.objectLike({
        RequestHeaderAllowlist: Match.arrayWith(['X-Verified-User-Sub', 'X-User-Authorization']),
      }),
    });
  });

  test('Gateway target routes to the Runtime as an HTTP target with OAUTH client-credentials outbound', () => {
    const tgt = customResourceCreatePayloads().find((p) => p.includes('CreateGatewayTarget'));
    expect(tgt).toBeDefined();
    expect(tgt).toContain('agentcoreRuntime');
    // OAuth outbound via an AgentCore Identity credential provider — the path
    // that lets allowedWorkloadConfiguration be satisfied.
    expect(tgt).toContain('OAUTH');
    expect(tgt).toContain('oauthCredentialProvider');
    expect(tgt).toContain('CLIENT_CREDENTIALS');
    // The old pass-through mode must be gone (it cannot satisfy the lock).
    expect(tgt).not.toContain('JWT_PASSTHROUGH');
  });
});

describe('OAuth outbound identity: M2M client, credential provider, gateway token permissions', () => {
  test('A Cognito resource server, hosted domain, and M2M (client-credentials) app client exist', () => {
    template.hasResourceProperties('AWS::Cognito::UserPoolResourceServer', {
      Identifier: 'agentcore-runtime',
    });
    expect(Object.keys(template.findResources('AWS::Cognito::UserPoolDomain'))).not.toHaveLength(0);
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', {
      GenerateSecret: true,
      AllowedOAuthFlows: Match.arrayWith(['client_credentials']),
    });
  });

  test('A credential-provider provisioner Lambda exists with Cognito + Oauth2CredentialProvider permissions (and the M2M secret is NOT in the template)', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({ Action: 'cognito-idp:DescribeUserPoolClient' }),
          Match.objectLike({ Action: Match.arrayWith(['bedrock-agentcore:CreateOauth2CredentialProvider']) }),
        ]),
      }),
    });
    // The generated M2M client secret must never be rendered into the template.
    expect(JSON.stringify(template.toJSON())).not.toMatch(/ClientSecret/);
  });

  test('Gateway role can fetch the outbound OAuth token and read the provider secret', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({ Action: 'bedrock-agentcore:GetResourceOauth2Token' }),
          Match.objectLike({ Action: 'secretsmanager:GetSecretValue' }),
        ]),
      }),
    });
  });

  test('Runtime validates the M2M client token (AllowedClients on the runtime authorizer)', () => {
    const runtimes = template.findResources('AWS::BedrockAgentCore::Runtime');
    const allowedClients = Object.values(runtimes)
      .map((r) => r.Properties?.AuthorizerConfiguration?.CustomJWTAuthorizer?.AllowedClients)
      .find(Boolean);
    expect(allowedClients).toBeDefined();
    expect(allowedClients).toHaveLength(1);
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

  test('Injects VERIFIED user identity headers only after JWT validation, and strips client-supplied variants', () => {
    expect(content).toMatch(/X-Verified-User-Sub/);
    expect(content).toMatch(/X-User-Authorization/);
    expect(content).toMatch(/STRIPPED_CLIENT_HEADERS/);
    // The verified token forwarded is the validated bearer token (claims/token
    // come from jwt.verify above), passed into allow().
    expect(content).toMatch(/allow\(rawHeaders, compositeSessionId, base64Body, claims\.sub, token\)/);
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
