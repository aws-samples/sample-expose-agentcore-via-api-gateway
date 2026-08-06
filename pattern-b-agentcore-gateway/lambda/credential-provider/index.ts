// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

/**
 * Custom-resource provisioner for an AgentCore Identity OAuth2 credential
 * provider (CognitoOauth2).
 *
 * WHY A DEDICATED LAMBDA (not AwsCustomResource): CreateOauth2CredentialProvider
 * requires the M2M app client's *secret*. If we passed that secret through an
 * AwsCustomResource's parameters it would be rendered into the CloudFormation
 * template / custom-resource event in plaintext — a secret leak. Instead this
 * Lambda reads the secret at deploy time via DescribeUserPoolClient and hands it
 * straight to AgentCore Identity, so the secret never appears in the template.
 *
 * The credential provider is what lets the Gateway obtain an outbound OAuth
 * token (client-credentials) via AgentCore Identity for the Runtime target.
 * That Identity-brokered path is what stamps the Gateway's workload identity
 * onto the forwarded request, which is what the runtime's
 * `allowedWorkloadConfiguration` validates. (JWT pass-through never touches
 * AgentCore Identity, so it cannot satisfy the workload lock — this credential
 * provider is the mechanism that makes the perimeter work.)
 */

import {
  CognitoIdentityProviderClient,
  DescribeUserPoolClientCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  BedrockAgentCoreControlClient,
  CreateOauth2CredentialProviderCommand,
  UpdateOauth2CredentialProviderCommand,
  DeleteOauth2CredentialProviderCommand,
} from '@aws-sdk/client-bedrock-agentcore-control';

interface ResourceProperties {
  ServiceToken: string;
  /** Cognito user pool that owns the M2M app client. */
  PoolId: string;
  /** M2M (client-credentials) app client id. */
  ClientId: string;
  /** Credential provider name (also the physical id). */
  Name: string;
  /** Hosted-UI OAuth2 endpoints derived from the user pool domain. */
  AuthorizationEndpoint: string;
  TokenEndpoint: string;
  /** OIDC issuer (cognito-idp URL, used for token verification metadata). */
  Issuer: string;
}

interface CfnEvent {
  RequestType: 'Create' | 'Update' | 'Delete';
  ResourceProperties: ResourceProperties;
  PhysicalResourceId?: string;
}

const cognito = new CognitoIdentityProviderClient({});
const agentcore = new BedrockAgentCoreControlClient({});

async function getClientSecret(poolId: string, clientId: string): Promise<string> {
  const res = await cognito.send(
    new DescribeUserPoolClientCommand({ UserPoolId: poolId, ClientId: clientId }),
  );
  const secret = res.UserPoolClient?.ClientSecret;
  if (!secret) {
    throw new Error(`User pool client ${clientId} has no client secret`);
  }
  return secret;
}

function providerInput(props: ResourceProperties, clientSecret: string) {
  return {
    name: props.Name,
    credentialProviderVendor: 'CognitoOauth2' as const,
    oauth2ProviderConfigInput: {
      includedOauth2ProviderConfig: {
        clientId: props.ClientId,
        clientSecret,
        authorizationEndpoint: props.AuthorizationEndpoint,
        tokenEndpoint: props.TokenEndpoint,
        issuer: props.Issuer,
      },
    },
  };
}

export async function handler(event: CfnEvent): Promise<{ PhysicalResourceId: string; Data?: Record<string, string> }> {
  const props = event.ResourceProperties;
  const name = props.Name;

  if (event.RequestType === 'Delete') {
    try {
      await agentcore.send(new DeleteOauth2CredentialProviderCommand({ name }));
    } catch (err) {
      // Idempotent delete — don't wedge a stack rollback if it's already gone.
      if ((err as { name?: string }).name !== 'ResourceNotFoundException') {
        throw err;
      }
    }
    return { PhysicalResourceId: name };
  }

  const clientSecret = await getClientSecret(props.PoolId, props.ClientId);
  const input = providerInput(props, clientSecret);

  let arn: string | undefined;
  if (event.RequestType === 'Create') {
    const res = await agentcore.send(new CreateOauth2CredentialProviderCommand(input));
    arn = res.credentialProviderArn;
  } else {
    // Update: try update-in-place, fall back to create if it was removed.
    try {
      const res = await agentcore.send(new UpdateOauth2CredentialProviderCommand(input));
      arn = res.credentialProviderArn;
    } catch (err) {
      if ((err as { name?: string }).name === 'ResourceNotFoundException') {
        const res = await agentcore.send(new CreateOauth2CredentialProviderCommand(input));
        arn = res.credentialProviderArn;
      } else {
        throw err;
      }
    }
  }

  return { PhysicalResourceId: name, Data: { ProviderArn: arn ?? '' } };
}
