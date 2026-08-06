# Securely Exposing Amazon Bedrock AgentCore Runtime

**Disclaimer**: This is sample code, for non-production usage. You should work with your security and legal teams to meet your organizational security, regulatory and compliance requirements before deployment.

[Amazon Bedrock AgentCore Runtime](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime.html) is a serverless environment for hosting AI agents and tools. Each user session runs in its own isolated microVM, and [AgentCore Identity](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html) gives your agents distinct identities and integrates with your identity provider (Amazon Cognito, Okta, …).

When you expose that runtime to end users through a web or mobile app, you still need a dedicated **secure entry layer**: something that authenticates each user, enforces authorization, and channels all traffic through a single controlled path. That is the [AWS shared responsibility model](https://aws.amazon.com/compliance/shared-responsibility-model/) in practice — **AWS secures the runtime; you secure the access to it.**

This repository holds **two deployable CDK reference architectures** for that entry layer. Pick the one that fits your organization:

| | Pattern A — API Gateway | Pattern B — AgentCore Gateway |
| --- | --- | --- |
| Directory | [`pattern-a-api-gateway/`](pattern-a-api-gateway/) | [`pattern-b-agentcore-gateway/`](pattern-b-agentcore-gateway/) |
| Entry point | Amazon API Gateway + Lambda Authorizer | Amazon Bedrock AgentCore Gateway (`CUSTOM_JWT` inbound) + REQUEST interceptor Lambda |
| "No bypass" perimeter | Runtime resource policy (`aws:SourceVpc`) + VPC endpoint security group | Runtime workload lock (`allowedWorkloadConfiguration`) |
| Components to operate | API Gateway, Lambda Authorizer, VPC, VPC endpoints, Proxy Lambda | AgentCore Gateway + interceptor Lambda (no VPC) |
| User identity to agent | User JWT forwarded unchanged (no SigV4) | Interceptor-injected verified headers (OAuth outbound M2M token) |
| AWS WAF | Attach yourself to the API stage | Integrated at the Gateway |
| Request timeout | Inherits API Gateway's integration timeout | Not subject to that limit |
| Endpoint | Can be fully private (API Gateway PRIVATE endpoint) | Public endpoint stays active; access gated by JWT authorizer + workload lock |
| Best suited to | Teams already standardized on API Gateway | Teams starting fresh who want less infrastructure to operate |

> A companion blog post walks through both patterns in narrative form and the decision criteria between them. This README is the technical entry point; each subdirectory has its own full walkthrough.

## What both patterns share

Both architectures implement the same **customer-side, defense-in-depth controls** — only the ingress plumbing differs:

1. **Inbound JWT validation** — the Cognito user JWT is validated at the edge (Lambda Authorizer in A / interceptor in B) *and* again at the runtime by AgentCore Identity.
2. **Session ownership binding** — the runtime session ID is a deterministic composite hash, `sha256(<X-Session-Id> : <jwtSub>)`, so two users reusing the same client session ID can never collide. The raw client session ID is never forwarded.
3. **Per-user / per-session throttling** — DynamoDB conditional writes enforce max sessions per user, max invocations per session, and a session TTL.
4. **Prompt-layer protection** — an Amazon Bedrock Guardrail screens every model invocation (prompt-attack detection, PII handling).
5. **Observability** — every authorization decision is logged as structured JSON to CloudWatch, with an `INVALID_JWT` metric filter + alarm.
6. **Fail-secure authorization** — any failed check results in a deny; there is no fail-open branch.

## The two patterns

### Pattern A — expose through Amazon API Gateway → [`pattern-a-api-gateway/`](pattern-a-api-gateway/)

API Gateway terminates each client connection. A REQUEST-type **Lambda Authorizer** validates the JWT, checks the `X-Session-Id` UUID, computes the composite session ID, and enforces throttling. On success, API Gateway forwards to a **Proxy Lambda in a private VPC** (no internet egress) that relays the request to the runtime through a `bedrock-agentcore` VPC endpoint, forwarding the user's token unchanged. The perimeter is enforced by the runtime **resource-based policy** (`aws:SourceVpc`) plus the VPC endpoint security group: a valid JWT sent directly to the runtime from outside the VPC is rejected. Before production, associate an AWS WAF Web ACL with the API stage yourself.

### Pattern B — expose through AgentCore Gateway → [`pattern-b-agentcore-gateway/`](pattern-b-agentcore-gateway/)

AgentCore Gateway is purpose-built for agentic traffic and combines ingress auth, egress auth, and the outbound runtime call in one managed service — no Proxy Lambda and no VPC to assemble. A `CUSTOM_JWT` inbound authorizer validates the JWT, then a **REQUEST interceptor Lambda** carries the same session-binding and throttling logic. For egress, the Gateway obtains an **OAuth client-credentials (M2M) token**, which stamps the Gateway's workload identity; the runtime's `allowedWorkloadConfiguration` verifies it, so the runtime can only be invoked *through the Gateway*. Because the M2M token replaces the user's token, the interceptor injects verified identity headers (`X-Verified-User-Sub`, `X-User-Authorization`) for on-behalf-of access. AWS WAF integrates directly at the Gateway.

## Repository layout

```
.
├── pattern-a-api-gateway/          # Pattern A — API Gateway + Lambda Authorizer + VPC proxy
│   └── README.md                   #   full walkthrough
├── pattern-b-agentcore-gateway/    # Pattern B — AgentCore Gateway + REQUEST interceptor
│   └── README.md                   #   full walkthrough
├── LICENSE                         # MIT-0 (shared)
├── CONTRIBUTING.md
└── CODE_OF_CONDUCT.md
```

Each pattern is a **self-contained CDK project** (its own `package.json`, stack, agent, scripts, and tests).

## Getting started

Clone the repo, then `cd` into the pattern you want and follow its README:

```bash
cd pattern-a-api-gateway      # or: cd pattern-b-agentcore-gateway
npm install
./scripts/deploy.sh
```

From there you can extend either pattern for multi-tenant use, add observability hooks, or tighten controls for your compliance requirements.

## Contributors

Meriem Smache, Christian Kamwangala, Lior Perez, Charline Boulie

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
