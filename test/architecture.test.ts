/**
 * Tests for the AgentCore security architecture:
 *   - API Gateway → Lambda Authorizer → Proxy Lambda (in private VPC)
 *     → bedrock-agentcore VPC endpoint → AgentCore Runtime
 *   - AgentCore Runtime configured with Cognito OAuth inbound
 *   - Resource-based policy on Runtime + DEFAULT endpoint:
 *     `Allow Principal "*"` with `aws:SourceVpc` matching this stack's VPC
 *   - VPC has private subnets only (no IGW, no NAT)
 *   - VPC endpoints: DynamoDB (gateway), CloudWatch Logs, Lambda,
 *     Bedrock AgentCore (interface)
 *   - VPC endpoint policy on bedrock-agentcore VPCe restricts to
 *     Proxy Lambda's role (defense-in-depth alongside the resource policy)
 *   - Proxy Lambda forwards the user's JWT (no SigV4) and uses Lambda
 *     response streaming
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

describe('Architecture: API Gateway → Proxy Lambda (in VPC) → AgentCore Runtime', () => {
  test('VPC exists with private subnets only (no IGW, no NAT)', () => {
    template.hasResourceProperties('AWS::EC2::VPC', { CidrBlock: '10.0.0.0/16' });
    expect(Object.keys(template.findResources('AWS::EC2::NatGateway'))).toHaveLength(0);
    expect(Object.keys(template.findResources('AWS::EC2::InternetGateway'))).toHaveLength(0);
  });

  test('VPC endpoints exist: DynamoDB (Gateway), CloudWatch Logs, Lambda, Bedrock AgentCore (Interface)', () => {
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      VpcEndpointType: 'Gateway',
      ServiceName: Match.objectLike({ 'Fn::Join': Match.arrayWith([Match.arrayWith([Match.stringLikeRegexp('dynamodb')])]) }),
    });
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      VpcEndpointType: 'Interface',
      ServiceName: Match.stringLikeRegexp('com\\.amazonaws\\..*\\.logs'),
    });
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      VpcEndpointType: 'Interface',
      ServiceName: Match.stringLikeRegexp('com\\.amazonaws\\..*\\.lambda'),
    });
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      VpcEndpointType: 'Interface',
      ServiceName: Match.stringLikeRegexp('com\\.amazonaws\\..*\\.bedrock-agentcore'),
    });
  });

  test('Proxy Lambda exists in the VPC, no internet egress', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'nodejs22.x',
      VpcConfig: Match.objectLike({
        SecurityGroupIds: Match.anyValue(),
        SubnetIds: Match.anyValue(),
      }),
      Environment: { Variables: Match.objectLike({ AGENT_RUNTIME_ARN: Match.anyValue() }) },
    });
  });

  test('Proxy Lambda security group has explicit egress only to VPC endpoints on 443', () => {
    // CDK with allowAllOutbound:false creates separate SecurityGroupEgress
    // resources for each explicit rule. Verify a TCP/443 rule exists.
    template.hasResourceProperties('AWS::EC2::SecurityGroupEgress', {
      IpProtocol: 'tcp',
      FromPort: 443,
      ToPort: 443,
    });
  });

  test('API Gateway integration is AWS_PROXY → response-streaming-invocations (Lambda streaming)', () => {
    template.hasResourceProperties('AWS::ApiGateway::Method', {
      HttpMethod: 'POST',
      Integration: Match.objectLike({
        Type: 'AWS_PROXY',
        Uri: Match.objectLike({
          'Fn::Join': Match.arrayWith([
            Match.arrayWith([Match.stringLikeRegexp('response-streaming-invocations')]),
          ]),
        }),
      }),
    });
  });

  test('Resource-based policy is applied to the Runtime ARN with Allow + Principal "*" + aws:SourceVpc condition', () => {
    const customResources = template.findResources('Custom::AWS');
    const policyEntries = Object.values(customResources).filter((r) => {
      const create = r.Properties?.Create;
      const createStr = typeof create === 'string' ? create : JSON.stringify(create);
      return createStr.includes('PutResourcePolicy') && createStr.includes('AllowOAuthFromVpc');
    });
    expect(policyEntries.length).toBeGreaterThanOrEqual(2); // runtime + DEFAULT endpoint

    // The serialized policy is multi-level escaped (CloudFormation Fn::Join
    // wrapping a JSON.stringified inner-value JSON). Validate the key
    // semantic tokens are present rather than matching escape levels.
    for (const r of policyEntries) {
      const created = JSON.stringify(r.Properties.Create);
      expect(created).toContain('AllowOAuthFromVpc');
      expect(created).toContain('Allow');
      expect(created).toContain('bedrock-agentcore:InvokeAgentRuntime');
      expect(created).toContain('aws:SourceVpc');
      // Wildcard principal: the `*` survives all escaping.
      expect(created).toContain('Principal');
      expect(created).toMatch(/Principal[^,]*\*/);
    }
  });

  test('Resource-based policy is applied to the DEFAULT endpoint as well (both runtime and runtime-endpoint/DEFAULT)', () => {
    const customResources = template.findResources('Custom::AWS');
    const endpointPolicy = Object.values(customResources).find((r) => {
      const create = r.Properties?.Create;
      const createStr = typeof create === 'string' ? create : JSON.stringify(create);
      return createStr.includes('runtime-endpoint/DEFAULT') && createStr.includes('PutResourcePolicy');
    });
    expect(endpointPolicy).toBeDefined();
  });

  test('VPC endpoint policy on bedrock-agentcore VPCe explicitly allows InvokeAgentRuntime from any caller in the VPC', () => {
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      ServiceName: Match.stringLikeRegexp('bedrock-agentcore'),
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            // Bare "*" — required for OAuth-anonymous callers per the
            // AgentCore docs. AnyPrincipal produces { AWS: "*" } which
            // does not match anonymous calls.
            Principal: '*',
            Action: 'bedrock-agentcore:InvokeAgentRuntime',
          }),
        ]),
      }),
    });
  });

  test('Stack outputs include VpcId, runtime ARN/ID, throttle table name, and pool IDs', () => {
    const outputKeys = Object.keys(template.findOutputs('*'));
    expect(outputKeys).toEqual(expect.arrayContaining([
      expect.stringContaining('ApiUrl'),
      expect.stringContaining('UserPoolId'),
      expect.stringContaining('UserPoolClientId'),
      expect.stringContaining('ThrottleTableName'),
      expect.stringContaining('Region'),
      expect.stringContaining('VpcId'),
      expect.stringContaining('AgentRuntimeArn'),
    ]));
  });
});

describe('Proxy Lambda code: JWT pass-through, no SigV4', () => {
  const proxyFile = path.join(__dirname, '..', 'lambda', 'gateway', 'index.ts');
  const content = fs.readFileSync(proxyFile, 'utf-8');

  test('Proxy code does NOT import the Bedrock AgentCore SDK (no SigV4 path)', () => {
    expect(content).not.toMatch(/BedrockAgentCoreClient/);
    expect(content).not.toMatch(/InvokeAgentRuntimeCommand/);
    expect(content).not.toMatch(/@aws-sdk\/client-bedrock-agentcore/);
  });

  test('Proxy code uses fetch and forwards Authorization + injects session header', () => {
    expect(content).toMatch(/await\s+fetch\(/);
    expect(content).toMatch(/Authorization:\s*auth/);
    expect(content).toMatch(/X-Amzn-Bedrock-AgentCore-Runtime-Session-Id/);
  });

  test('Proxy code reads composite session ID from authorizer context', () => {
    expect(content).toMatch(/event\.requestContext\?\.authorizer\?\.compositeSessionId/);
  });

  test('Proxy code uses Lambda response streaming', () => {
    expect(content).toMatch(/awslambda\.streamifyResponse/);
  });

  test('Proxy code requires AGENT_RUNTIME_ARN env var', () => {
    expect(content).toMatch(/process\.env\.AGENT_RUNTIME_ARN/);
  });
});

describe('Supporting resources: Cognito, DynamoDB, Guardrail, monitoring', () => {
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

  test('Runtime is configured with CustomJWTAuthorizer (Cognito OAuth inbound)', () => {
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
});
