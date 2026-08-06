#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { AgentCoreSecurityStack } from '../lib/agentcore-security-stack';

const app = new cdk.App();
cdk.Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

// Local test-run override: distinct stack name so we don't touch the existing
// AgentCoreSecurityStack (Pattern A) already deployed in this account/region.
new AgentCoreSecurityStack(app, 'AgentCoreSecurityStackPatternB', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
  },
  description: 'Defense-in-depth security for Amazon Bedrock AgentCore Runtime',
});
