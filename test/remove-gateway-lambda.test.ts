/**
 * Tests for the throttle-only DynamoDB architecture:
 * - Gateway Lambda is a thin proxy (no DynamoDB, no session checks)
 * - Authorizer validates JWTs, derives composite session IDs, and applies throttling
 * - DynamoDB table is used only for per-user / per-session counters
 */

import * as cdk from 'aws-cdk-lib';
import { Match, Template } from 'aws-cdk-lib/assertions';
import * as fs from 'fs';
import * as path from 'path';
import { AgentCoreSecurityStack } from '../lib/agentcore-security-stack';

describe('Gateway Lambda should NOT have DynamoDB dependency', () => {
  let template: Template;

  beforeAll(() => {
    const app = new cdk.App();
    const stack = new AgentCoreSecurityStack(app, 'TestStack', {
      env: { account: '123456789012', region: 'us-east-1' },
    });
    template = Template.fromStack(stack);
  });

  test('Proxy Lambda should NOT have any throttle/session table env var', () => {
    const lambdas = template.findResources('AWS::Lambda::Function');
    const proxyKeys = Object.keys(lambdas).filter((key) =>
      key.toLowerCase().includes('proxyfn'),
    );
    expect(proxyKeys.length).toBeGreaterThan(0);

    for (const key of proxyKeys) {
      const envVars = lambdas[key]?.Properties?.Environment?.Variables ?? {};
      expect(envVars).not.toHaveProperty('SESSIONS_TABLE_NAME');
      expect(envVars).not.toHaveProperty('THROTTLE_TABLE_NAME');
    }
  });

  test('Gateway Lambda source should NOT import DynamoDB clients', () => {
    const gatewayFile = path.join(__dirname, '..', 'lambda', 'gateway', 'index.ts');
    const content = fs.readFileSync(gatewayFile, 'utf-8');
    expect(content).not.toMatch(/DynamoDBClient/);
    expect(content).not.toMatch(/DynamoDBDocumentClient/);
    expect(content).not.toMatch(/GetCommand/);
  });

  test('Gateway Lambda source should NOT have session validation logic', () => {
    const gatewayFile = path.join(__dirname, '..', 'lambda', 'gateway', 'index.ts');
    const content = fs.readFileSync(gatewayFile, 'utf-8');
    expect(content).not.toMatch(/SESSION_NOT_FOUND/);
    expect(content).not.toMatch(/SESSION_INACTIVE/);
    expect(content).not.toMatch(/getSession/);
  });

  test('Authorizer source should NOT perform DynamoDB session binding lookup', () => {
    const authFile = path.join(__dirname, '..', 'lambda', 'authorizer', 'index.ts');
    const content = fs.readFileSync(authFile, 'utf-8');
    // These legacy code paths belonged to the session-binding check that has
    // been superseded by the composite hash.
    expect(content).not.toMatch(/SessionRecord/);
    expect(content).not.toMatch(/verifySessionBinding/);
    expect(content).not.toMatch(/SESSION_BINDING_MISMATCH/);
    expect(content).not.toMatch(/session\.ownerId/);
  });

  test('Shared types should NOT export SessionRecord', () => {
    const typesFile = path.join(__dirname, '..', 'lambda', 'shared', 'types.ts');
    const content = fs.readFileSync(typesFile, 'utf-8');
    expect(content).not.toMatch(/export\s+interface\s+SessionRecord/);
    expect(content).not.toMatch(/export\s+interface\s+InvokeRequest/);
    expect(content).not.toMatch(/export\s+interface\s+InvokeResponse/);
  });
});

describe('Preservation: Resources that must survive the refactor', () => {
  let template: Template;

  beforeAll(() => {
    const app = new cdk.App();
    const stack = new AgentCoreSecurityStack(app, 'PreservationTestStack', {
      env: { account: '123456789012', region: 'us-east-1' },
    });
    template = Template.fromStack(stack);
  });

  test('Lambda Authorizer exists with NODEJS_20_X runtime and env vars', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'nodejs22.x',
      Environment: {
        Variables: Match.objectLike({
          THROTTLE_TABLE_NAME: Match.anyValue(),
          COGNITO_ISSUER: Match.anyValue(),
          MAX_SESSIONS_PER_USER: Match.anyValue(),
          MAX_INVOCATIONS_PER_SESSION: Match.anyValue(),
          SESSION_TTL_HOURS: Match.anyValue(),
        }),
      },
    });
  });

  test('REQUEST-type Lambda Authorizer is attached to the API', () => {
    template.hasResourceProperties('AWS::ApiGateway::Authorizer', {
      Type: 'REQUEST',
    });
  });

  test('VPC exists with no IGW and no NAT', () => {
    template.hasResourceProperties('AWS::EC2::VPC', { CidrBlock: '10.0.0.0/16' });
    expect(Object.keys(template.findResources('AWS::EC2::NatGateway'))).toHaveLength(0);
    expect(Object.keys(template.findResources('AWS::EC2::InternetGateway'))).toHaveLength(0);
  });

  test('VPC endpoints exist: DynamoDB, CloudWatch, Lambda, Bedrock AgentCore', () => {
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      ServiceName: Match.objectLike({ 'Fn::Join': Match.arrayWith([Match.arrayWith([Match.stringLikeRegexp('dynamodb')])]) }),
      VpcEndpointType: 'Gateway',
    });
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', { ServiceName: Match.stringLikeRegexp('logs'), VpcEndpointType: 'Interface' });
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', { ServiceName: Match.stringLikeRegexp('lambda'), VpcEndpointType: 'Interface' });
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', { ServiceName: Match.stringLikeRegexp('bedrock-agentcore'), VpcEndpointType: 'Interface' });
  });

  test('CloudWatch INVALID_JWT metric filter and alarm exist', () => {
    template.hasResourceProperties('AWS::Logs::MetricFilter', { FilterPattern: 'INVALID_JWT' });
    template.hasResourceProperties('AWS::CloudWatch::Alarm', { Threshold: 5 });
  });

  test('Cognito UserPool and UserPoolClient exist', () => {
    template.hasResourceProperties('AWS::Cognito::UserPool', { UserPoolName: 'agentcore-security-users' });
    template.hasResourceProperties('AWS::Cognito::UserPoolClient', { ClientName: 'agentcore-security-client' });
  });

  test('DynamoDB throttle table exists with `pk` partition key and TTL', () => {
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      KeySchema: Match.arrayWith([Match.objectLike({ AttributeName: 'pk', KeyType: 'HASH' })]),
      TimeToLiveSpecification: { AttributeName: 'expiresAt', Enabled: true },
    });
  });

  test('CfnOutputs exist', () => {
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

  test('Shared types preserved', () => {
    const typesFile = path.join(__dirname, '..', 'lambda', 'shared', 'types.ts');
    const content = fs.readFileSync(typesFile, 'utf-8');
    expect(content).toMatch(/export\s+interface\s+JWTClaims/);
    expect(content).toMatch(/export\s+interface\s+AuthorizerEvent/);
    expect(content).toMatch(/export\s+interface\s+AuthorizerResponse/);
    expect(content).toMatch(/export\s+interface\s+ThrottleRecord/);
  });
});
