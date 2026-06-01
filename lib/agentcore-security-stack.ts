/**
 * AgentCoreSecurityStack — defense-in-depth for Amazon Bedrock AgentCore Runtime.
 *
 * Architecture:
 *   API Gateway → Lambda Authorizer → Proxy Lambda (in private VPC)
 *   → bedrock-agentcore VPC endpoint → AgentCore Runtime (OAuth inbound)
 *
 * The user's Cognito JWT is validated twice — once at API Gateway by a
 * custom Lambda Authorizer (which also enforces UUID v4 on X-Session-Id,
 * computes a user-bound composite session ID, and applies per-user /
 * per-session throttling), and again at AgentCore Runtime by AgentCore
 * Identity using the Cognito user pool's discovery URL. The Proxy Lambda
 * forwards the user's JWT unchanged (no SigV4) and exists solely to give
 * the call a VPC-resident origin so the AgentCore Runtime resource-based
 * policy can enforce `aws:SourceVpc`.
 *
 * Customer-side controls implemented:
 *   1. JWT validation at API Gateway — Lambda Authorizer + Cognito JWKS
 *   2. Session ownership binding     — runtimeSessionId = sha256(uuid:jwtSub)
 *   3. Per-user / per-session throttling — DynamoDB conditional writes
 *   4. OAuth inbound at the Runtime  — AgentCore Identity (Cognito JWT)
 *   5. Network perimeter             — VPC endpoint policy + Runtime
 *                                      resource-based policy with aws:SourceVpc
 *   6. Prompt-layer protection       — Amazon Bedrock Guardrails
 *   7. Observability                 — CloudWatch logs + INVALID_JWT alarm
 */

import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaNodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as bedrock from 'aws-cdk-lib/aws-bedrock';
import * as agentcore from '@aws-cdk/aws-bedrock-agentcore-alpha';
import {
  AwsCustomResource,
  AwsCustomResourcePolicy,
  PhysicalResourceId,
} from 'aws-cdk-lib/custom-resources';
import { NagSuppressions } from 'cdk-nag';
import { Construct } from 'constructs';
import * as path from 'path';

export interface AgentCoreSecurityStackProps extends cdk.StackProps {
  /** Override the VPC CIDR (default: 10.0.0.0/16). */
  vpcCidr?: string;
}

export class AgentCoreSecurityStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: AgentCoreSecurityStackProps) {
    super(scope, id, props);

    const vpcCidr = props?.vpcCidr ?? '10.0.0.0/16';

    // =====================================================================
    // AUTHENTICATION (Cognito) — used both by the API Gateway Lambda
    // Authorizer and by the AgentCore Runtime's inbound JWT authorizer.
    // =====================================================================

    const userPool = new cognito.UserPool(this, 'UserPool', {
      userPoolName: 'agentcore-security-users',
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      autoVerify: { email: true },
      passwordPolicy: {
        minLength: 8,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const userPoolClient = new cognito.UserPoolClient(this, 'UserPoolClient', {
      userPool,
      userPoolClientName: 'agentcore-security-client',
      authFlows: { userPassword: true, userSrp: true },
      generateSecret: false,
    });

    // =====================================================================
    // THROTTLE TABLE — partition key `pk` with synthetic prefixed keys:
    //   - `USER#<sub>`                       — active session count per user
    //   - `INVOCATIONS#<compositeSessionId>` — invocation count per session
    // Session binding is enforced by the composite hash itself; this table
    // is throttling-only.
    // =====================================================================

    const throttleTable = new dynamodb.Table(this, 'ThrottleTable', {
      tableName: `agentcore-throttle-${cdk.Names.uniqueId(this).slice(-8)}`,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expiresAt',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // =====================================================================
    // LAMBDA AUTHORIZER — JWT validation, composite session hashing,
    // throttling. Runs outside the VPC so it can reach Cognito JWKS and
    // DynamoDB over the public service endpoints.
    // =====================================================================

    const authorizerLogGroup = new logs.LogGroup(this, 'AuthorizerLogGroup', {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const authorizerFn = new lambdaNodejs.NodejsFunction(this, 'AuthorizerFn', {
      entry: path.join(__dirname, '..', 'lambda', 'authorizer', 'index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
      memorySize: 256,
      logGroup: authorizerLogGroup,
      environment: {
        THROTTLE_TABLE_NAME: throttleTable.tableName,
        COGNITO_ISSUER: `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`,
        MAX_SESSIONS_PER_USER: '5',
        MAX_INVOCATIONS_PER_SESSION: '100',
        SESSION_TTL_HOURS: '24',
      },
      bundling: { minify: true, sourceMap: true },
    });

    throttleTable.grantReadWriteData(authorizerFn);

    // =====================================================================
    // BEDROCK GUARDRAIL — prompt-injection detection + PII protection,
    // applied by AgentCore Runtime on every model invocation.
    // =====================================================================

    const guardrail = new bedrock.CfnGuardrail(this, 'AgentGuardrail', {
      name: `agentcore-security-guardrail-${cdk.Names.uniqueId(this).slice(-8)}`,
      description: 'Prompt injection detection and PII protection for the AgentCore security sample',
      blockedInputMessaging: 'Your request was blocked by our safety controls.',
      blockedOutputsMessaging: 'The response was blocked by our safety controls.',
      contentPolicyConfig: {
        filtersConfig: [
          { type: 'PROMPT_ATTACK', inputStrength: 'HIGH', outputStrength: 'NONE' },
        ],
      },
      sensitiveInformationPolicyConfig: {
        piiEntitiesConfig: [
          { type: 'EMAIL', action: 'ANONYMIZE' },
          { type: 'PHONE', action: 'ANONYMIZE' },
          { type: 'US_SOCIAL_SECURITY_NUMBER', action: 'BLOCK' },
          { type: 'CREDIT_DEBIT_CARD_NUMBER', action: 'BLOCK' },
        ],
      },
    });

    const guardrailVersion = new bedrock.CfnGuardrailVersion(this, 'AgentGuardrailVersion', {
      guardrailIdentifier: guardrail.attrGuardrailId,
      description: 'Initial version',
    });

    // =====================================================================
    // AGENTCORE RUNTIME — OAuth inbound (Cognito) so the user's JWT is
    // validated by AgentCore Identity directly. No SigV4 swap needed.
    // =====================================================================

    const agentRuntime = new agentcore.Runtime(this, 'AgentCoreRuntime', {
      runtimeName: 'securitySampleAgent',
      description: 'Strands agent for the security reference architecture',
      authorizerConfiguration: agentcore.RuntimeAuthorizerConfiguration.usingCognito(
        userPool,
        [userPoolClient],
      ),
      agentRuntimeArtifact: agentcore.AgentRuntimeArtifact.fromCodeAsset({
        path: path.join(__dirname, '..', '.build', 'agent'),
        runtime: agentcore.AgentCoreRuntime.PYTHON_3_12,
        entrypoint: ['handler.py'],
      }),
      environmentVariables: {
        MODEL_ID: 'global.amazon.nova-2-lite-v1:0',
        GUARDRAIL_ID: guardrail.attrGuardrailId,
        GUARDRAIL_VERSION: guardrailVersion.attrVersion,
      },
    });

    // Grant the runtime's execution role permission to invoke the Bedrock model.
    // Strands Agents uses the Converse API (ConverseStream).
    agentRuntime.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'bedrock:InvokeModel',
        'bedrock:InvokeModelWithResponseStream',
        'bedrock:Converse',
        'bedrock:ConverseStream',
      ],
      resources: [
        `arn:aws:bedrock:${this.region}::foundation-model/amazon.nova-2-lite-v1:0`,
        `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/global.amazon.nova-2-lite-v1:0`,
        `arn:aws:bedrock:*::foundation-model/amazon.nova-2-lite-v1:0`,
      ],
    }));

    agentRuntime.addToRolePolicy(new iam.PolicyStatement({
      actions: ['bedrock:ApplyGuardrail'],
      resources: [guardrail.attrGuardrailArn],
    }));

    // =====================================================================
    // NETWORKING — private subnets, no IGW, no NAT
    // =====================================================================

    const vpc = new ec2.Vpc(this, 'SecurityVpc', {
      ipAddresses: ec2.IpAddresses.cidr(vpcCidr),
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [{
        name: 'Private',
        subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
        cidrMask: 24,
      }],
    });

    const flowLogGroup = new logs.LogGroup(this, 'VpcFlowLogGroup', {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    vpc.addFlowLog('FlowLog', {
      destination: ec2.FlowLogDestination.toCloudWatchLogs(flowLogGroup),
      trafficType: ec2.FlowLogTrafficType.ALL,
    });

    const lambdaSg = new ec2.SecurityGroup(this, 'LambdaSg', {
      vpc,
      description: 'Security group for Proxy Lambda — outbound to VPC endpoints on 443',
      allowAllOutbound: false,
    });

    const vpcEndpointSg = new ec2.SecurityGroup(this, 'VpcEndpointSg', {
      vpc,
      description: 'Security group for VPC endpoints — inbound from Lambda SG on 443',
      allowAllOutbound: false,
    });

    lambdaSg.addEgressRule(vpcEndpointSg, ec2.Port.tcp(443), 'Allow Lambda to reach VPC endpoints');
    vpcEndpointSg.addIngressRule(lambdaSg, ec2.Port.tcp(443), 'Allow inbound from Lambda functions');

    vpc.addGatewayEndpoint('DynamoDbEndpoint', {
      service: ec2.GatewayVpcEndpointAwsService.DYNAMODB,
    });

    vpc.addInterfaceEndpoint('CloudWatchLogsEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      securityGroups: [vpcEndpointSg],
      privateDnsEnabled: true,
    });

    vpc.addInterfaceEndpoint('LambdaEndpoint', {
      service: ec2.InterfaceVpcEndpointAwsService.LAMBDA,
      securityGroups: [vpcEndpointSg],
      privateDnsEnabled: true,
    });

    const bedrockEndpoint = vpc.addInterfaceEndpoint('BedrockAgentCoreEndpoint', {
      service: new ec2.InterfaceVpcEndpointService(`com.amazonaws.${this.region}.bedrock-agentcore`),
      securityGroups: [vpcEndpointSg],
      privateDnsEnabled: true,
    });

    // =====================================================================
    // PROXY LAMBDA — JWT pass-through (no SigV4). Runs in private subnets
    // so the call to AgentCore exits through the VPC endpoint, populating
    // aws:SourceVpc and aws:SourceVpce in the request context.
    // =====================================================================

    const proxyFn = new lambdaNodejs.NodejsFunction(this, 'ProxyFn', {
      entry: path.join(__dirname, '..', 'lambda', 'gateway', 'index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      securityGroups: [lambdaSg],
      environment: {
        AGENT_RUNTIME_ARN: agentRuntime.agentRuntimeArn,
      },
      bundling: { minify: true, sourceMap: true },
    });

    // =====================================================================
    // VPC ENDPOINT POLICY — only the Proxy Lambda's role can use the
    // bedrock-agentcore VPCe. Defense in depth alongside the Runtime
    // resource-based policy below.
    // =====================================================================

    bedrockEndpoint.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      principals: [new iam.ArnPrincipal(proxyFn.role!.roleArn)],
      actions: ['bedrock-agentcore:*'],
      resources: ['*'],
    }));

    bedrockEndpoint.addToPolicy(new iam.PolicyStatement({
      effect: iam.Effect.DENY,
      principals: [new iam.AnyPrincipal()],
      actions: ['*'],
      resources: ['*'],
      conditions: { StringNotEquals: { 'aws:PrincipalArn': proxyFn.role!.roleArn } },
    }));

    // =====================================================================
    // RESOURCE-BASED POLICY ON AGENTCORE RUNTIME (via AwsCustomResource).
    //
    // OAuth-inbound pattern from the AgentCore docs: wildcard principal
    // (AgentCore Identity validates the JWT before policy evaluation),
    // gated by aws:SourceVpc so requests must enter through this stack's
    // VPC. AgentCore evaluates the policy at both the Runtime ARN and
    // its DEFAULT endpoint, so the policy is attached to both.
    // =====================================================================

    const runtimeEndpointArn = `${agentRuntime.agentRuntimeArn}/runtime-endpoint/DEFAULT`;

    const buildOAuthVpcPolicy = (resourceArn: string): string => JSON.stringify({
      Version: '2012-10-17',
      Statement: [{
        Sid: 'AllowOAuthFromVpc',
        Effect: 'Allow',
        Principal: '*',
        Action: 'bedrock-agentcore:InvokeAgentRuntime',
        Resource: resourceArn,
        Condition: {
          StringEquals: { 'aws:SourceVpc': vpc.vpcId },
        },
      }],
    });

    const runtimePolicyCr = new AwsCustomResource(this, 'RuntimeResourcePolicy', {
      onCreate: {
        service: 'bedrock-agentcore-control',
        action: 'PutResourcePolicy',
        parameters: {
          resourceArn: agentRuntime.agentRuntimeArn,
          policy: buildOAuthVpcPolicy(agentRuntime.agentRuntimeArn),
        },
        physicalResourceId: PhysicalResourceId.of(`${agentRuntime.agentRuntimeArn}#policy`),
      },
      onUpdate: {
        service: 'bedrock-agentcore-control',
        action: 'PutResourcePolicy',
        parameters: {
          resourceArn: agentRuntime.agentRuntimeArn,
          policy: buildOAuthVpcPolicy(agentRuntime.agentRuntimeArn),
        },
        physicalResourceId: PhysicalResourceId.of(`${agentRuntime.agentRuntimeArn}#policy`),
      },
      onDelete: {
        service: 'bedrock-agentcore-control',
        action: 'DeleteResourcePolicy',
        parameters: { resourceArn: agentRuntime.agentRuntimeArn },
        ignoreErrorCodesMatching: 'ResourceNotFoundException',
      },
      policy: AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: [
            'bedrock-agentcore:PutResourcePolicy',
            'bedrock-agentcore:DeleteResourcePolicy',
          ],
          resources: [agentRuntime.agentRuntimeArn, runtimeEndpointArn],
        }),
      ]),
      installLatestAwsSdk: true,
    });

    const endpointPolicyCr = new AwsCustomResource(this, 'RuntimeEndpointResourcePolicy', {
      onCreate: {
        service: 'bedrock-agentcore-control',
        action: 'PutResourcePolicy',
        parameters: {
          resourceArn: runtimeEndpointArn,
          policy: buildOAuthVpcPolicy(runtimeEndpointArn),
        },
        physicalResourceId: PhysicalResourceId.of(`${runtimeEndpointArn}#policy`),
      },
      onUpdate: {
        service: 'bedrock-agentcore-control',
        action: 'PutResourcePolicy',
        parameters: {
          resourceArn: runtimeEndpointArn,
          policy: buildOAuthVpcPolicy(runtimeEndpointArn),
        },
        physicalResourceId: PhysicalResourceId.of(`${runtimeEndpointArn}#policy`),
      },
      onDelete: {
        service: 'bedrock-agentcore-control',
        action: 'DeleteResourcePolicy',
        parameters: { resourceArn: runtimeEndpointArn },
        ignoreErrorCodesMatching: 'ResourceNotFoundException',
      },
      policy: AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: [
            'bedrock-agentcore:PutResourcePolicy',
            'bedrock-agentcore:DeleteResourcePolicy',
          ],
          resources: [agentRuntime.agentRuntimeArn, runtimeEndpointArn],
        }),
      ]),
      installLatestAwsSdk: true,
    });

    runtimePolicyCr.node.addDependency(agentRuntime);
    endpointPolicyCr.node.addDependency(agentRuntime);

    // =====================================================================
    // REST API GATEWAY — Lambda integration to the Proxy Lambda (in VPC),
    // with response streaming for token-by-token UX.
    // =====================================================================

    const apiLogGroup = new logs.LogGroup(this, 'ApiAccessLogGroup', {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const api = new apigateway.RestApi(this, 'SecurityApi', {
      restApiName: 'agentcore-security-api',
      description: 'Defense-in-depth secured API for AgentCore Runtime',
      deployOptions: {
        stageName: 'v1',
        accessLogDestination: new apigateway.LogGroupLogDestination(apiLogGroup),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields(),
        loggingLevel: apigateway.MethodLoggingLevel.INFO,
      },
    });

    const authorizer = new apigateway.RequestAuthorizer(this, 'SessionBindingAuthorizer', {
      handler: authorizerFn,
      identitySources: [
        apigateway.IdentitySource.header('Authorization'),
        apigateway.IdentitySource.header('X-Session-Id'),
      ],
      resultsCacheTtl: cdk.Duration.seconds(0),
    });

    const invokeResource = api.root.addResource('invoke');

    invokeResource.addMethod('POST',
      new apigateway.LambdaIntegration(proxyFn),
      {
        authorizer,
        authorizationType: apigateway.AuthorizationType.CUSTOM,
        requestParameters: {
          'method.request.header.Authorization': true,
          'method.request.header.X-Session-Id': true,
        },
      },
    );

    // Enable response streaming — override the L1 integration to use the
    // Lambda response-streaming invocation endpoint and STREAM transfer
    // mode. CDK's L2 doesn't expose this yet.
    const cfnMethod = invokeResource.node.findChild('POST').node.defaultChild as apigateway.CfnMethod;
    cfnMethod.addPropertyOverride('Integration.Uri',
      `arn:aws:apigateway:${this.region}:lambda:path/2021-11-15/functions/${proxyFn.functionArn}/response-streaming-invocations`,
    );
    cfnMethod.addPropertyOverride('Integration.ResponseTransferMode', 'STREAM');
    cfnMethod.addPropertyOverride('Integration.TimeoutInMillis', 120000);

    // Force a new API deployment so the stage picks up the streaming config.
    // CDK's auto-deployment only detects L2 changes; L1 overrides are invisible.
    const deployment = new apigateway.Deployment(this, 'StreamingDeployment', { api });
    (api.deploymentStage.node.defaultChild as apigateway.CfnStage).addPropertyOverride(
      'DeploymentId', deployment.node.defaultChild && (deployment.node.defaultChild as cdk.CfnResource).ref,
    );

    proxyFn.addPermission('ApiGwStreamingInvoke', {
      principal: new iam.ServicePrincipal('apigateway.amazonaws.com'),
      action: 'lambda:InvokeFunctionUrl',
      sourceArn: api.arnForExecuteApi('POST', '/invoke', '*'),
    });

    // =====================================================================
    // MONITORING — INVALID_JWT metric filter + alarm
    // =====================================================================

    const invalidJwtFilter = new logs.MetricFilter(this, 'InvalidJwtFilter', {
      logGroup: authorizerLogGroup,
      filterPattern: logs.FilterPattern.literal('INVALID_JWT'),
      metricNamespace: 'AgentCoreSecurity',
      metricName: 'InvalidJwt',
      metricValue: '1',
    });

    new cloudwatch.Alarm(this, 'InvalidJwtAlarm', {
      alarmName: 'AgentCore-InvalidJwt-High',
      alarmDescription: 'Triggered when invalid JWT denials exceed threshold',
      metric: invalidJwtFilter.metric({ statistic: 'Sum', period: cdk.Duration.minutes(5) }),
      threshold: 5,
      evaluationPeriods: 1,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // =====================================================================
    // CDK-NAG SUPPRESSIONS — justified exceptions for sample code
    // =====================================================================

    NagSuppressions.addResourceSuppressions(userPool, [
      { id: 'AwsSolutions-COG2', reason: 'MFA not required for sample test users — admin-created only, selfSignUpEnabled: false' },
      { id: 'AwsSolutions-COG8', reason: 'Cognito Plus tier adds cost — not needed for a sample/demo' },
    ]);

    NagSuppressions.addResourceSuppressions(throttleTable, [
      { id: 'AwsSolutions-DDB3', reason: 'PITR not needed — ephemeral throttle counters with TTL auto-expiry' },
    ]);

    NagSuppressions.addResourceSuppressions(api, [
      { id: 'AwsSolutions-APIG2', reason: 'Request validation handled by Lambda Authorizer (JWT, UUID v4 format) and AgentCore Identity (JWT)' },
    ]);

    NagSuppressions.addResourceSuppressions(api, [
      { id: 'AwsSolutions-APIG3', reason: 'WAF documented as recommended addition in README — not included to keep sample focused on AgentCore security controls' },
    ], true);

    NagSuppressions.addResourceSuppressions(invokeResource, [
      { id: 'AwsSolutions-COG4', reason: 'Uses custom Lambda Authorizer by design — JWT validation + composite session hashing + throttling, not a Cognito authorizer' },
    ], true);

    const lambdasForNag: lambdaNodejs.NodejsFunction[] = [authorizerFn, proxyFn];
    NagSuppressions.addResourceSuppressions(lambdasForNag, [
      { id: 'AwsSolutions-L1', reason: 'Using NODEJS_22_X — cdk-nag has not yet added it to the latest-runtime allowlist' },
      {
        id: 'AwsSolutions-IAM4',
        reason: 'AWS managed policies (AWSLambdaBasicExecutionRole, AWSLambdaVPCAccessExecutionRole) are standard for Lambda functions',
        appliesTo: [
          'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
          'Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole',
        ],
      },
    ], true);

    NagSuppressions.addResourceSuppressions(api, [
      {
        id: 'AwsSolutions-IAM4',
        reason: 'AWS managed policy for API Gateway CloudWatch logging is standard',
        appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs'],
      },
    ], true);

    NagSuppressions.addResourceSuppressions(agentRuntime, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'Wildcards in AgentCore Runtime execution role are generated by the alpha CDK construct — not user-controlled. Log group wildcards required for runtime logging.',
      },
    ], true);

    // VPC endpoint security group cannot resolve VPC CIDR intrinsic in cdk-nag.
    const vpcEndpointSgConstruct = this.node.findChild('VpcEndpointSg') as Construct;
    NagSuppressions.addResourceSuppressions(vpcEndpointSgConstruct, [
      { id: 'CdkNagValidationFailure', reason: 'EC23 cannot resolve VPC CIDR intrinsic — security group only allows inbound from Lambda SG on 443' },
    ]);

    NagSuppressions.addResourceSuppressions(proxyFn, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'Runtime ARN/* wildcard required to invoke AgentCore Runtime endpoints (DEFAULT endpoint)',
        appliesTo: [{ regex: '/^Resource::.*AgentRuntimeArn.*\\*$/g' }],
      },
    ], true);

    // AwsCustomResource instantiates a shared singleton Lambda at the stack
    // root. Suppress on the construct node directly so it works regardless
    // of stack ID.
    const crSingleton = this.node.findChild('AWS679f53fac002430cb0da5b7982bd2287') as Construct | undefined;
    if (crSingleton) {
      NagSuppressions.addResourceSuppressions(crSingleton, [
        { id: 'AwsSolutions-L1', reason: 'AwsCustomResource provisions its own Lambda — runtime controlled by CDK, not user-configurable' },
        {
          id: 'AwsSolutions-IAM4',
          reason: 'AwsCustomResource uses the AWS-managed AWSLambdaBasicExecutionRole by design',
          appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
        },
      ], true);
    }

    // =====================================================================
    // STACK OUTPUTS
    // =====================================================================

    new cdk.CfnOutput(this, 'ApiUrl', { value: api.url, description: 'API Gateway endpoint URL' });
    new cdk.CfnOutput(this, 'UserPoolId', { value: userPool.userPoolId, description: 'Cognito User Pool ID' });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: userPoolClient.userPoolClientId, description: 'Cognito User Pool Client ID' });
    new cdk.CfnOutput(this, 'ThrottleTableName', { value: throttleTable.tableName, description: 'DynamoDB throttle table name' });
    new cdk.CfnOutput(this, 'Region', { value: this.region, description: 'AWS Region' });
    new cdk.CfnOutput(this, 'AgentRuntimeArn', { value: agentRuntime.agentRuntimeArn, description: 'AgentCore Runtime ARN' });
    new cdk.CfnOutput(this, 'AgentRuntimeId', { value: agentRuntime.agentRuntimeId, description: 'AgentCore Runtime ID' });
    new cdk.CfnOutput(this, 'GuardrailId', { value: guardrail.attrGuardrailId, description: 'Bedrock Guardrail ID' });
    new cdk.CfnOutput(this, 'VpcId', { value: vpc.vpcId, description: 'VPC ID' });
  }
}
