/**
 * AgentCoreSecurityStack — defense-in-depth for Amazon Bedrock AgentCore Runtime,
 * fronted by an AgentCore Gateway (MCP-less HTTP target) instead of API Gateway.
 *
 * Architecture (OAuth inbound + OAUTH client-credentials outbound):
 *   Client → AgentCore Gateway (CUSTOM_JWT inbound, Cognito)
 *          → REQUEST interceptor Lambda (JWT + UUID + composite hash + throttle
 *            + verified-identity injection)
 *          → AgentCore Runtime (OAuth inbound, OAUTH client-credentials outbound)
 *
 * The user's Cognito JWT is validated at the Gateway (CUSTOM_JWT inbound) and
 * again in the interceptor (defense in depth + to read `sub`, emit INVALID_JWT
 * telemetry, and forward a trusted identity). The Gateway's Runtime target uses
 * OAUTH client-credentials outbound: it fetches a machine token from an AgentCore
 * Identity credential provider (backed by a Cognito M2M client) and forwards THAT
 * to the Runtime. That Identity-brokered token is what stamps the Gateway's
 * workload identity so the Runtime's allowedWorkloadConfiguration is satisfied —
 * JWT pass-through cannot do this (verified live: "Transaction token required").
 * Because the Runtime's Authorization is now the Gateway's M2M token, the
 * interceptor forwards the verified user identity (X-Verified-User-Sub /
 * X-User-Authorization) so the agent can still act on behalf of the user (OBO).
 *
 * The "no bypass" perimeter that used to be enforced by a VPC + aws:SourceVpc
 * resource policy is now enforced natively: the Runtime's
 * customJWTAuthorizer.allowedWorkloadConfiguration allows ONLY this Gateway's
 * workload to invoke the Runtime. A valid JWT sent directly (e.g. from a laptop)
 * is rejected because its identity chain does not include the Gateway.
 *
 * Customer-side controls implemented:
 *   1. JWT validation at the Gateway (CUSTOM_JWT) + interceptor
 *   2. Session ownership binding     — runtimeSessionId = sha256(uuid:jwtSub)
 *   3. OBO — OAUTH outbound stamps the workload id; interceptor injects the
 *            verified user identity headers the runtime allowlists to the agent
 *   4. Per-user / per-session throttling — DynamoDB conditional writes
 *   5. Runtime perimeter             — allowedWorkloadConfiguration locks the
 *                                      runtime to this Gateway's workload only
 *   6. Prompt-layer protection       — Amazon Bedrock Guardrails (in-agent)
 *   7. Observability                 — CloudWatch logs + INVALID_JWT alarm
 *
 * NOTE ON CDK ESCAPE HATCHES: the alpha construct (2.248.0-alpha.0) is MCP-only
 * and CloudFormation still requires a protocolType on the gateway and exposes no
 * `http.agentcoreRuntime` target or `allowedWorkloadConfiguration`. Path 1 needs
 * a protocol-less gateway with a Runtime HTTP target and the workload lock, so
 * the Gateway, its interceptor, its Runtime target, and the workload restriction
 * are provisioned via AwsCustomResource against bedrock-agentcore-control — the
 * same pattern the sample already used for the runtime resource policy.
 */

import * as cdk from 'aws-cdk-lib';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as lambdaNodejs from 'aws-cdk-lib/aws-lambda-nodejs';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as bedrock from 'aws-cdk-lib/aws-bedrock';
import * as s3assets from 'aws-cdk-lib/aws-s3-assets';
import * as agentcore from '@aws-cdk/aws-bedrock-agentcore-alpha';
import { CfnRuntime } from 'aws-cdk-lib/aws-bedrockagentcore';
import {
  AwsCustomResource,
  AwsCustomResourcePolicy,
  PhysicalResourceId,
  PhysicalResourceIdReference,
  Provider,
} from 'aws-cdk-lib/custom-resources';
import { NagSuppressions } from 'cdk-nag';
import { Construct } from 'constructs';
import * as path from 'path';

export interface AgentCoreSecurityStackProps extends cdk.StackProps {}

export class AgentCoreSecurityStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: AgentCoreSecurityStackProps) {
    super(scope, id, props);

    const uniqueSuffix = cdk.Names.uniqueId(this).slice(-8).toLowerCase();

    // =====================================================================
    // AUTHENTICATION (Cognito) — used by the Gateway CUSTOM_JWT inbound
    // authorizer, the interceptor's JWT re-validation, and the Runtime's
    // OAuth inbound authorizer.
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

    const cognitoIssuer = `https://cognito-idp.${this.region}.amazonaws.com/${userPool.userPoolId}`;
    const discoveryUrl = `${cognitoIssuer}/.well-known/openid-configuration`;

    // =====================================================================
    // OUTBOUND (M2M) IDENTITY — used by the Gateway's OAuth outbound auth to
    // the Runtime target. The Gateway does NOT forward the user's raw token to
    // the runtime; instead it obtains a client-credentials token via AgentCore
    // Identity. That Identity-brokered exchange is what stamps the Gateway's
    // workload identity onto the request, which is what the runtime's
    // `allowedWorkloadConfiguration` validates. (JWT pass-through never touches
    // AgentCore Identity and therefore cannot satisfy the workload lock — this
    // is the mechanism that makes the "no bypass" perimeter actually work.)
    //
    // The user's identity still reaches the agent: the interceptor validates
    // the user JWT and injects verified identity headers (see the interceptor
    // and the runtime RequestHeaderConfiguration below).
    // =====================================================================

    const invokeScope = new cognito.ResourceServerScope({
      scopeName: 'invoke',
      scopeDescription: 'Invoke the runtime through the gateway',
    });
    const runtimeResourceServer = userPool.addResourceServer('RuntimeResourceServer', {
      identifier: 'agentcore-runtime',
      scopes: [invokeScope],
    });
    // Full scope string as it appears in the token: "<identifier>/<scopeName>".
    const m2mScope = 'agentcore-runtime/invoke';

    // Hosted domain — Cognito only exposes a working OAuth2 token endpoint
    // (for the client-credentials grant) through a hosted domain; the OIDC
    // discovery URL alone does not serve client-credentials.
    const userPoolDomain = userPool.addDomain('OboDomain', {
      cognitoDomain: { domainPrefix: `agentcore-sec-${uniqueSuffix}` },
    });

    // Machine-to-machine app client the Gateway uses for outbound tokens.
    // generateSecret: the secret is read at deploy time by the credential-
    // provider provisioner Lambda (never rendered into the template).
    const m2mClient = new cognito.UserPoolClient(this, 'M2mClient', {
      userPool,
      userPoolClientName: 'agentcore-m2m-client',
      generateSecret: true,
      oAuth: {
        flows: { clientCredentials: true },
        scopes: [cognito.OAuthScope.resourceServer(runtimeResourceServer, invokeScope)],
      },
    });
    m2mClient.node.addDependency(runtimeResourceServer);

    // AgentCore Identity OAuth2 credential provider (CognitoOauth2). Created by
    // a dedicated provisioner Lambda so the M2M client secret is read at deploy
    // time (via DescribeUserPoolClient) and handed straight to AgentCore
    // Identity — it never lands in the CloudFormation template. See
    // lambda/credential-provider/index.ts for the rationale.
    const credentialProviderName = `agentcore-cog-m2m-${uniqueSuffix}`;

    const credentialProviderFn = new lambdaNodejs.NodejsFunction(this, 'CredentialProviderProvisioner', {
      entry: path.join(__dirname, '..', 'lambda', 'credential-provider', 'index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(60),
      memorySize: 256,
      bundling: {
        minify: true,
        sourceMap: true,
        // The Lambda runtime provides @aws-sdk/client-cognito-identity-provider,
        // but NOT @aws-sdk/client-bedrock-agentcore-control (newer client), so
        // override the default '@aws-sdk/*' external list to bundle the latter.
        externalModules: ['@aws-sdk/client-cognito-identity-provider'],
      },
    });
    credentialProviderFn.addToRolePolicy(new iam.PolicyStatement({
      actions: ['cognito-idp:DescribeUserPoolClient'],
      resources: [userPool.userPoolArn],
    }));
    credentialProviderFn.addToRolePolicy(new iam.PolicyStatement({
      // Credential-provider ARNs are server-generated, so scope to the account's
      // default token vault rather than an unknown-at-synth ARN.
      actions: [
        'bedrock-agentcore:CreateOauth2CredentialProvider',
        'bedrock-agentcore:UpdateOauth2CredentialProvider',
        'bedrock-agentcore:DeleteOauth2CredentialProvider',
        'bedrock-agentcore:GetOauth2CredentialProvider',
        // CreateOauth2CredentialProvider lazily ensures the account's default
        // token vault exists on first use, so the provisioner must be able to
        // create/get it.
        'bedrock-agentcore:CreateTokenVault',
        'bedrock-agentcore:GetTokenVault',
      ],
      resources: [
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:token-vault/default`,
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:token-vault/default/*`,
      ],
    }));
    // AgentCore Identity stores the credential provider's client secret in a
    // service-managed Secrets Manager secret, created/updated/deleted using the
    // CALLER's credentials — so the provisioner needs these on that managed
    // prefix. Scoped to bedrock-agentcore-identity!default/oauth2/*.
    credentialProviderFn.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        'secretsmanager:CreateSecret',
        'secretsmanager:PutSecretValue',
        'secretsmanager:UpdateSecret',
        'secretsmanager:DescribeSecret',
        'secretsmanager:GetSecretValue',
        'secretsmanager:TagResource',
        'secretsmanager:DeleteSecret',
      ],
      resources: [
        `arn:aws:secretsmanager:${this.region}:${this.account}:secret:bedrock-agentcore-identity!default/oauth2/*`,
      ],
    }));

    const credentialProviderProvider = new Provider(this, 'CredentialProviderProvider', {
      onEventHandler: credentialProviderFn,
    });

    const credentialProviderCr = new cdk.CustomResource(this, 'OauthCredentialProvider', {
      serviceToken: credentialProviderProvider.serviceToken,
      properties: {
        PoolId: userPool.userPoolId,
        ClientId: m2mClient.userPoolClientId,
        Name: credentialProviderName,
        AuthorizationEndpoint: `${userPoolDomain.baseUrl()}/oauth2/authorize`,
        TokenEndpoint: `${userPoolDomain.baseUrl()}/oauth2/token`,
        Issuer: cognitoIssuer,
      },
    });
    credentialProviderCr.node.addDependency(m2mClient);
    credentialProviderCr.node.addDependency(userPoolDomain);
    const credentialProviderArn = credentialProviderCr.getAttString('ProviderArn');

    // =====================================================================
    // THROTTLE TABLE — partition key `pk` with synthetic prefixed keys:
    //   - `USER#<sub>`                       — active session count per user
    //   - `INVOCATIONS#<compositeSessionId>` — invocation count per session
    // =====================================================================

    const throttleTable = new dynamodb.Table(this, 'ThrottleTable', {
      tableName: `agentcore-throttle-${uniqueSuffix}`,
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'expiresAt',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // =====================================================================
    // REQUEST INTERCEPTOR LAMBDA — JWT validation, composite session hashing,
    // throttling, structured audit logging, fail-secure short-circuit deny.
    // Runs outside any VPC so it can reach Cognito JWKS + DynamoDB over the
    // public service endpoints. Invoked by the Gateway's execution role.
    // =====================================================================

    const interceptorLogGroup = new logs.LogGroup(this, 'InterceptorLogGroup', {
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const interceptorFn = new lambdaNodejs.NodejsFunction(this, 'InterceptorFn', {
      entry: path.join(__dirname, '..', 'lambda', 'interceptor', 'index.ts'),
      handler: 'handler',
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: cdk.Duration.seconds(10),
      memorySize: 256,
      logGroup: interceptorLogGroup,
      environment: {
        THROTTLE_TABLE_NAME: throttleTable.tableName,
        COGNITO_ISSUER: cognitoIssuer,
        MAX_SESSIONS_PER_USER: '5',
        MAX_INVOCATIONS_PER_SESSION: '100',
        SESSION_TTL_HOURS: '24',
      },
      bundling: { minify: true, sourceMap: true },
    });

    throttleTable.grantReadWriteData(interceptorFn);

    // =====================================================================
    // BEDROCK GUARDRAIL — prompt-injection detection + PII protection,
    // applied by the agent on every model invocation.
    // =====================================================================

    const guardrail = new bedrock.CfnGuardrail(this, 'AgentGuardrail', {
      name: `agentcore-security-guardrail-${uniqueSuffix}`,
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
    // GATEWAY EXECUTION ROLE — assumed by the AgentCore Gateway service to
    // (a) invoke the REQUEST interceptor Lambda and (b) invoke the Runtime
    // target. Scoped to only those resources (least privilege).
    // =====================================================================

    const gatewayRole = new iam.Role(this, 'GatewayExecutionRole', {
      assumedBy: new iam.ServicePrincipal('bedrock-agentcore.amazonaws.com', {
        conditions: {
          StringEquals: { 'aws:SourceAccount': this.account },
        },
      }),
      description: 'Execution role for the AgentCore Gateway fronting the Runtime',
    });

    interceptorFn.grantInvoke(gatewayRole);

    // The Gateway assumes this role to create its own workload identity (the
    // identity that stamps forwarded requests, which the runtime's
    // allowedWorkloadConfiguration checks). AWS's auto-created gateway role
    // includes these; since we build a custom least-privilege role, we must
    // grant them explicitly — otherwise the gateway fails to create
    // dependencies ("not authorized to CreateWorkloadIdentity") and goes FAILED.
    gatewayRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        'bedrock-agentcore:CreateWorkloadIdentity',
        'bedrock-agentcore:GetWorkloadIdentity',
        'bedrock-agentcore:UpdateWorkloadIdentity',
        'bedrock-agentcore:DeleteWorkloadIdentity',
        'bedrock-agentcore:ListWorkloadIdentities',
        'bedrock-agentcore:GetWorkloadAccessToken',
        'bedrock-agentcore:GetWorkloadAccessTokenForJWT',
        'bedrock-agentcore:GetWorkloadAccessTokenForUserId',
      ],
      resources: [
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:workload-identity-directory/default`,
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:workload-identity-directory/default/workload-identity/*`,
      ],
    }));

    // OAuth outbound to the Runtime target: the Gateway assumes this role to
    // fetch a client-credentials token from AgentCore Identity
    // (GetResourceOauth2Token, keyed on the Gateway's workload identity) and to
    // read the credential provider's stored client secret from Secrets Manager.
    // Without these the outbound token fetch fails and the runtime never sees a
    // request. This is the OAuth-outbound counterpart that makes the workload
    // lock satisfiable (JWT pass-through needs none of this — and cannot satisfy
    // the lock).
    gatewayRole.addToPolicy(new iam.PolicyStatement({
      actions: ['bedrock-agentcore:GetResourceOauth2Token'],
      resources: [
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:token-vault/default`,
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:token-vault/default/*`,
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:workload-identity-directory/default`,
        `arn:aws:bedrock-agentcore:${this.region}:${this.account}:workload-identity-directory/default/workload-identity/*`,
      ],
    }));
    gatewayRole.addToPolicy(new iam.PolicyStatement({
      actions: ['secretsmanager:GetSecretValue'],
      resources: [
        `arn:aws:secretsmanager:${this.region}:${this.account}:secret:bedrock-agentcore-identity!default/oauth2/*`,
      ],
    }));

    // =====================================================================
    // AGENTCORE GATEWAY (via AwsCustomResource) — protocol-less so it can
    // host an AgentCore Runtime HTTP target, CUSTOM_JWT (Cognito) inbound,
    // with the REQUEST interceptor attached (passRequestHeaders=true so the
    // interceptor sees Authorization + X-Session-Id).
    // =====================================================================

    const gatewayName = `agentcore-security-gw-${uniqueSuffix}`;

    const gatewayCr = new AwsCustomResource(this, 'AgentCoreGateway', {
      onCreate: {
        service: 'bedrock-agentcore-control',
        action: 'CreateGateway',
        parameters: {
          name: gatewayName,
          roleArn: gatewayRole.roleArn,
          // No protocolType — required for AgentCore Runtime (HTTP) targets.
          authorizerType: 'CUSTOM_JWT',
          authorizerConfiguration: {
            customJWTAuthorizer: {
              discoveryUrl,
              allowedClients: [userPoolClient.userPoolClientId],
            },
          },
          interceptorConfigurations: [{
            interceptor: { lambda: { arn: interceptorFn.functionArn } },
            interceptionPoints: ['REQUEST'],
            inputConfiguration: { passRequestHeaders: true },
          }],
        },
        physicalResourceId: PhysicalResourceId.fromResponse('gatewayId'),
      },
      onDelete: {
        service: 'bedrock-agentcore-control',
        action: 'DeleteGateway',
        parameters: { gatewayIdentifier: new PhysicalResourceIdReference() },
        // Don't wedge rollback if the gateway was never created / already gone.
        ignoreErrorCodesMatching: 'ValidationException|ResourceNotFoundException|AccessDeniedException',
      },
      // All bedrock-agentcore control-plane actions used by ANY of the three
      // custom resources are granted here, on the FIRST custom resource. All
      // three share one provider role, and this policy is proven to propagate
      // before its own CreateGateway call succeeds — so by the time the target
      // and workload-lock calls run, the shared role already carries these
      // permissions. This avoids the IAM eventual-consistency race that occurs
      // when each custom resource relies on its own just-created inline policy.
      policy: AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: [
            'bedrock-agentcore:CreateGateway',
            'bedrock-agentcore:DeleteGateway',
            'bedrock-agentcore:GetGateway',
            'bedrock-agentcore:UpdateGateway',
            'bedrock-agentcore:CreateGatewayTarget',
            'bedrock-agentcore:DeleteGatewayTarget',
            'bedrock-agentcore:GetGatewayTarget',
            'bedrock-agentcore:UpdateAgentRuntime',
            'bedrock-agentcore:GetAgentRuntime',
            // CreateGateway creates the gateway's workload identity synchronously
            // using the CALLER's credentials (this provider role), so the caller
            // — not just the gateway execution role — needs these.
            'bedrock-agentcore:CreateWorkloadIdentity',
            'bedrock-agentcore:GetWorkloadIdentity',
            'bedrock-agentcore:UpdateWorkloadIdentity',
            'bedrock-agentcore:DeleteWorkloadIdentity',
            'bedrock-agentcore:ListWorkloadIdentities',
          ],
          resources: ['*'],
        }),
        // iam:PassRole for the roles this stack passes to the bedrock-agentcore
        // service: the gateway role (CreateGateway) and the runtime execution
        // role (UpdateAgentRuntime). Scoped to this stack's roles and gated on
        // the service they're passed to. Placed on the gateway CR (the reliably
        // early-propagating policy on the shared provider role) so all three
        // custom resources are authorized without an IAM propagation race.
        new iam.PolicyStatement({
          actions: ['iam:PassRole'],
          resources: [`arn:aws:iam::${this.account}:role/${this.stackName}-*`],
          conditions: {
            StringEquals: { 'iam:PassedToService': 'bedrock-agentcore.amazonaws.com' },
          },
        }),
      ]),
      installLatestAwsSdk: true,
    });
    gatewayCr.node.addDependency(gatewayRole);
    // Critical: the gateway assumes this role to create its workload identity
    // and invoke the interceptor DURING gateway creation. Those permissions
    // live on the role's DefaultPolicy (a separate resource). Depending only on
    // the Role lets CloudFormation create the gateway before the policy is
    // attached → "not authorized to CreateWorkloadIdentity" → gateway FAILED.
    // Depend on the DefaultPolicy so the permissions exist first.
    const gatewayRoleDefaultPolicy = gatewayRole.node.tryFindChild('DefaultPolicy');
    if (gatewayRoleDefaultPolicy) {
      gatewayCr.node.addDependency(gatewayRoleDefaultPolicy);
    }

    const gatewayId = gatewayCr.getResponseField('gatewayId');
    const gatewayArn = gatewayCr.getResponseField('gatewayArn');
    const gatewayUrl = gatewayCr.getResponseField('gatewayUrl');

    // =====================================================================
    // AGENTCORE RUNTIME — OAuth inbound (Cognito). Two escape-hatch props are
    // layered onto the underlying CfnRuntime:
    //   - allowedWorkloadConfiguration → locks invocation to this Gateway
    //     (replaces the old aws:SourceVpc perimeter).
    //   - requestHeaderConfiguration   → allowlist Authorization so the passed-
    //     through JWT reaches the agent for OBO claim extraction.
    // =====================================================================

    // The Strands agent code, uploaded to the CDK asset bucket. Declared
    // explicitly (rather than via AgentRuntimeArtifact.fromCodeAsset, which
    // creates the asset lazily during synth) so we hold a concrete reference:
    // the RuntimeWorkloadLock custom resource below re-supplies this artifact
    // to UpdateAgentRuntime, and AgentCore retrieves the zip from S3 using the
    // CALLER's credentials — so the custom-resource provider role must be
    // granted read on this object (see the grant on RuntimeWorkloadLock).
    const agentCodeAsset = new s3assets.Asset(this, 'AgentCodeAsset', {
      path: path.join(__dirname, '..', '.build', 'agent'),
    });

    const agentRuntime = new agentcore.Runtime(this, 'AgentCoreRuntime', {
      runtimeName: 'securitySampleAgent',
      description: 'Strands agent for the security reference architecture',
      authorizerConfiguration: agentcore.RuntimeAuthorizerConfiguration.usingCognito(
        userPool,
        // The runtime validates the Gateway's outbound client-credentials token
        // (client_id = the M2M app client), NOT the end-user token. The user's
        // identity reaches the agent via interceptor-injected verified headers.
        [m2mClient],
      ),
      agentRuntimeArtifact: agentcore.AgentRuntimeArtifact.fromS3(
        {
          bucketName: agentCodeAsset.s3BucketName,
          objectKey: agentCodeAsset.s3ObjectKey,
        },
        agentcore.AgentCoreRuntime.PYTHON_3_12,
        ['handler.py'],
      ),
      environmentVariables: {
        MODEL_ID: 'global.amazon.nova-2-lite-v1:0',
        GUARDRAIL_ID: guardrail.attrGuardrailId,
        GUARDRAIL_VERSION: guardrailVersion.attrVersion,
      },
    });

    const cfnRuntime = agentRuntime.node.defaultChild as CfnRuntime;

    // OBO: allowlist the interceptor-injected VERIFIED user identity headers
    // through to the agent. The runtime's own Authorization now carries the
    // Gateway's M2M token (not the user's), so the user identity is propagated
    // via these headers, which the interceptor sets only after validating the
    // user's JWT. (RequestHeaderConfiguration IS supported by the CFN resource.)
    cfnRuntime.addPropertyOverride('RequestHeaderConfiguration.RequestHeaderAllowlist', ['X-Verified-User-Sub', 'X-User-Authorization']);

    // Perimeter (allowedWorkloadConfiguration) is applied AFTER creation via an
    // UpdateAgentRuntime custom resource below, because the CloudFormation
    // AWS::BedrockAgentCore::Runtime schema does not yet accept
    // AllowedWorkloadConfiguration ("Unsupported property"). See the workload-lock
    // custom resource further down and the deploy-time notes in
    // .kiro/steering/security-invariants.md.

    // Grant the runtime's execution role permission to invoke the Bedrock model
    // and apply the guardrail.
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

    // The Gateway execution role must be able to invoke the Runtime target.
    // Use a literal runtime-wildcard ARN (not agentRuntime.agentRuntimeArn) so
    // this policy does NOT create a dependency edge on the Runtime resource —
    // the Runtime depends on the Gateway (for the workload lock), and the
    // Gateway custom resource passes this role, so referencing the concrete
    // Runtime ARN here would form a create-time dependency cycle.
    gatewayRole.addToPolicy(new iam.PolicyStatement({
      actions: ['bedrock-agentcore:InvokeAgentRuntime'],
      resources: [`arn:aws:bedrock-agentcore:${this.region}:${this.account}:runtime/*`],
    }));

    // =====================================================================
    // GATEWAY TARGET (via AwsCustomResource) — the AgentCore Runtime as an
    // HTTP target with OAUTH (client-credentials) outbound auth. The Gateway
    // fetches a token from the AgentCore Identity credential provider; this
    // Identity-brokered path is what stamps the Gateway workload identity so
    // the runtime's allowedWorkloadConfiguration accepts the call. Created
    // after the Gateway, the Runtime, and the credential provider exist.
    // =====================================================================

    const targetCr = new AwsCustomResource(this, 'AgentCoreGatewayTarget', {
      onCreate: {
        service: 'bedrock-agentcore-control',
        action: 'CreateGatewayTarget',
        parameters: {
          gatewayIdentifier: gatewayId,
          name: 'runtime',
          targetConfiguration: {
            http: {
              agentcoreRuntime: {
                arn: agentRuntime.agentRuntimeArn,
                qualifier: 'DEFAULT',
              },
            },
          },
          credentialProviderConfigurations: [
            {
              credentialProviderType: 'OAUTH',
              credentialProvider: {
                oauthCredentialProvider: {
                  providerArn: credentialProviderArn,
                  grantType: 'CLIENT_CREDENTIALS',
                  scopes: [m2mScope],
                },
              },
            },
          ],
        },
        physicalResourceId: PhysicalResourceId.fromResponse('targetId'),
      },
      onDelete: {
        service: 'bedrock-agentcore-control',
        action: 'DeleteGatewayTarget',
        parameters: {
          gatewayIdentifier: gatewayId,
          targetId: new PhysicalResourceIdReference(),
        },
        // If create failed, the physical ID is not a real targetId — don't wedge
        // rollback trying to delete it.
        ignoreErrorCodesMatching: 'ValidationException|ResourceNotFoundException|AccessDeniedException',
      },
      policy: AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: [
            'bedrock-agentcore:CreateGatewayTarget',
            'bedrock-agentcore:DeleteGatewayTarget',
            'bedrock-agentcore:GetGatewayTarget',
          ],
          resources: ['*'],
        }),
      ]),
      installLatestAwsSdk: true,
    });
    targetCr.node.addDependency(gatewayCr);
    targetCr.node.addDependency(agentRuntime);
    targetCr.node.addDependency(credentialProviderCr);

    // =====================================================================
    // RUNTIME WORKLOAD LOCK (via AwsCustomResource) — apply
    // allowedWorkloadConfiguration to the runtime AFTER creation, because the
    // CloudFormation resource schema rejects the property at create time.
    // UpdateAgentRuntime is a full PUT, so we re-supply the artifact, network,
    // role, and header allowlist and add the workload restriction to the
    // authorizer. The artifact is reused from the L1 (camelCase codeConfiguration).
    // =====================================================================

    const workloadLockAuthorizer = {
      customJWTAuthorizer: {
        discoveryUrl,
        // The runtime validates the Gateway's outbound client-credentials token
        // (client_id = M2M app client), not the end-user token.
        allowedClients: [m2mClient.userPoolClientId],
        allowedWorkloadConfiguration: {
          hostingEnvironments: [{ arn: gatewayArn }],
        },
      },
    };
    // Verified user identity headers the interceptor injects (after validating
    // the user JWT) are allowlisted through to the agent for OBO.
    const runtimeHeaderAllowlist = { requestHeaderAllowlist: ['X-Verified-User-Sub', 'X-User-Authorization'] };

    const runtimeWorkloadLock = new AwsCustomResource(this, 'RuntimeWorkloadLock', {
      onCreate: {
        service: 'bedrock-agentcore-control',
        action: 'UpdateAgentRuntime',
        parameters: {
          agentRuntimeId: agentRuntime.agentRuntimeId,
          agentRuntimeArtifact: cfnRuntime.agentRuntimeArtifact,
          networkConfiguration: { networkMode: 'PUBLIC' },
          roleArn: agentRuntime.role.roleArn,
          authorizerConfiguration: workloadLockAuthorizer,
          requestHeaderConfiguration: runtimeHeaderAllowlist,
        },
        physicalResourceId: PhysicalResourceId.of(`${agentRuntime.agentRuntimeId}#workload-lock`),
      },
      onUpdate: {
        service: 'bedrock-agentcore-control',
        action: 'UpdateAgentRuntime',
        parameters: {
          agentRuntimeId: agentRuntime.agentRuntimeId,
          agentRuntimeArtifact: cfnRuntime.agentRuntimeArtifact,
          networkConfiguration: { networkMode: 'PUBLIC' },
          roleArn: agentRuntime.role.roleArn,
          authorizerConfiguration: workloadLockAuthorizer,
          requestHeaderConfiguration: runtimeHeaderAllowlist,
        },
        physicalResourceId: PhysicalResourceId.of(`${agentRuntime.agentRuntimeId}#workload-lock`),
      },
      // No onDelete — the runtime (and thus its config) is deleted with the stack.
      policy: AwsCustomResourcePolicy.fromStatements([
        new iam.PolicyStatement({
          actions: ['bedrock-agentcore:UpdateAgentRuntime'],
          resources: [agentRuntime.agentRuntimeArn, `${agentRuntime.agentRuntimeArn}/*`],
        }),
        new iam.PolicyStatement({
          actions: ['iam:PassRole'],
          resources: [agentRuntime.role.roleArn],
        }),
        // UpdateAgentRuntime is a full PUT that re-supplies the S3 code artifact.
        // AgentCore retrieves/validates that zip from S3 using the CALLER's
        // credentials (this custom-resource provider role), so it must be able
        // to read the agent code object. Without this, UpdateAgentRuntime fails
        // with "Access denied when trying to retrieve zip file from S3" — even
        // though CreateRuntime (run by the privileged CFN execution role)
        // succeeded. Scoped to just the agent code object.
        new iam.PolicyStatement({
          actions: ['s3:GetObject', 's3:GetObjectVersion'],
          resources: [agentCodeAsset.bucket.arnForObjects(agentCodeAsset.s3ObjectKey)],
        }),
      ]),
      installLatestAwsSdk: true,
    });
    runtimeWorkloadLock.node.addDependency(agentRuntime);
    runtimeWorkloadLock.node.addDependency(gatewayCr);
    runtimeWorkloadLock.node.addDependency(targetCr);

    // =====================================================================
    // MONITORING — INVALID_JWT metric filter + alarm on the interceptor logs.
    // =====================================================================

    const invalidJwtFilter = new logs.MetricFilter(this, 'InvalidJwtFilter', {
      logGroup: interceptorLogGroup,
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

    NagSuppressions.addResourceSuppressions(interceptorFn, [
      { id: 'AwsSolutions-L1', reason: 'Using NODEJS_22_X — cdk-nag has not yet added it to the latest-runtime allowlist' },
      {
        id: 'AwsSolutions-IAM4',
        reason: 'AWS managed policy AWSLambdaBasicExecutionRole is standard for Lambda functions',
        appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
      },
    ], true);

    NagSuppressions.addResourceSuppressions(gatewayRole, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'Runtime/DEFAULT-endpoint ARNs are explicit; workload-identity and token-vault sub-resources (for GetResourceOauth2Token) and the AgentCore Identity managed secret are addressed by pattern because their ids are server-generated. Secret access is scoped to the bedrock-agentcore-identity!default/oauth2/ prefix.',
      },
    ], true);

    NagSuppressions.addResourceSuppressions(credentialProviderFn, [
      { id: 'AwsSolutions-L1', reason: 'Using NODEJS_22_X — cdk-nag has not yet added it to the latest-runtime allowlist' },
      {
        id: 'AwsSolutions-IAM4',
        reason: 'AWS managed policy AWSLambdaBasicExecutionRole is standard for Lambda functions',
        appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
      },
      {
        id: 'AwsSolutions-IAM5',
        reason: 'OAuth2 credential-provider ARNs are server-generated; scoped to the account default token vault (token-vault/default/*).',
      },
    ], true);

    // The cr.Provider framework provisions its own onEvent Lambda + role.
    const credProviderFramework = this.node.tryFindChild('CredentialProviderProvider');
    if (credProviderFramework) {
      NagSuppressions.addResourceSuppressions(credProviderFramework, [
        { id: 'AwsSolutions-L1', reason: 'cr.Provider framework Lambda runtime is managed by CDK, not user-configurable' },
        {
          id: 'AwsSolutions-IAM4',
          reason: 'cr.Provider framework role uses the AWS-managed AWSLambdaBasicExecutionRole by design',
          appliesTo: ['Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'],
        },
        {
          id: 'AwsSolutions-IAM5',
          reason: 'cr.Provider framework grants lambda:InvokeFunction to the onEvent handler with a version wildcard by design',
        },
      ], true);
    }

    NagSuppressions.addResourceSuppressions(agentRuntime, [
      {
        id: 'AwsSolutions-IAM5',
        reason: 'Wildcards in the AgentCore Runtime execution role are generated by the alpha CDK construct and required for runtime logging.',
      },
    ], true);

    // AgentCore control-plane custom resources need bedrock-agentcore:* on '*'
    // because gateway/target ARNs are server-generated and not known at synth.
    for (const cr of ['AgentCoreGateway', 'AgentCoreGatewayTarget', 'RuntimeWorkloadLock']) {
      const crNode = this.node.tryFindChild(cr);
      if (crNode) {
        NagSuppressions.addResourceSuppressions(crNode, [
          { id: 'AwsSolutions-IAM5', reason: 'Gateway/target/runtime ARNs and their sub-resources are addressed by pattern; actions are limited to specific gateway/runtime create/update/delete/get operations.' },
        ], true);
      }
    }

    // AwsCustomResource provisions a shared singleton Lambda at the stack root.
    const crSingleton = this.node.tryFindChild('AWS679f53fac002430cb0da5b7982bd2287') as Construct | undefined;
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

    new cdk.CfnOutput(this, 'GatewayUrl', { value: gatewayUrl, description: 'AgentCore Gateway MCP/invocation URL' });
    new cdk.CfnOutput(this, 'GatewayId', { value: gatewayId, description: 'AgentCore Gateway ID' });
    new cdk.CfnOutput(this, 'GatewayArn', { value: gatewayArn, description: 'AgentCore Gateway ARN (workload allowed to invoke the Runtime)' });
    new cdk.CfnOutput(this, 'UserPoolId', { value: userPool.userPoolId, description: 'Cognito User Pool ID' });
    new cdk.CfnOutput(this, 'UserPoolClientId', { value: userPoolClient.userPoolClientId, description: 'Cognito User Pool Client ID' });
    new cdk.CfnOutput(this, 'M2mClientId', { value: m2mClient.userPoolClientId, description: 'Cognito M2M client id (Gateway outbound client-credentials; runtime allowedClients)' });
    new cdk.CfnOutput(this, 'ThrottleTableName', { value: throttleTable.tableName, description: 'DynamoDB throttle table name' });
    new cdk.CfnOutput(this, 'Region', { value: this.region, description: 'AWS Region' });
    new cdk.CfnOutput(this, 'AgentRuntimeArn', { value: agentRuntime.agentRuntimeArn, description: 'AgentCore Runtime ARN' });
    new cdk.CfnOutput(this, 'AgentRuntimeId', { value: agentRuntime.agentRuntimeId, description: 'AgentCore Runtime ID' });
    new cdk.CfnOutput(this, 'GuardrailId', { value: guardrail.attrGuardrailId, description: 'Bedrock Guardrail ID' });
  }
}
