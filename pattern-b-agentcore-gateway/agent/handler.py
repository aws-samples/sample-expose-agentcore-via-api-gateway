# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

"""
Strands Agents agent for the AgentCore Runtime Security Sample.

This agent is deployed to Amazon Bedrock AgentCore Runtime and serves as the
backend for the security reference architecture. It is fronted by an AgentCore
Gateway that validates the caller's Cognito JWT (CUSTOM_JWT inbound), runs a
REQUEST interceptor (session binding + throttling + verified-identity
injection), and forwards the request to this runtime using OAUTH
client-credentials outbound (so the runtime's ``allowedWorkloadConfiguration``
perimeter is satisfied).

Because the Gateway target uses OAUTH client-credentials outbound (so the
runtime's ``allowedWorkloadConfiguration`` perimeter is satisfied), the runtime's
``Authorization`` header carries the Gateway's M2M token — NOT the user's. The
user's identity still reaches the agent: the REQUEST interceptor validates the
user JWT and injects verified identity headers that the runtime allowlists
through to the agent:

  * ``X-Verified-User-Sub``     — the validated user's ``sub``
  * ``X-User-Authorization``    — the validated user's original bearer token
                                  (``Bearer <jwt>``), for downstream OBO / 3LO

We decode the forwarded user token here WITHOUT re-validating the signature —
the interceptor already validated it. This is the on-behalf-of (OBO) hook where
the agent can act as the authenticated user.

The handler uses async streaming so AgentCore can progressively send response
chunks back through the Gateway.
"""

import os
import json
import logging

import jwt
from bedrock_agentcore.runtime import BedrockAgentCoreApp

logger = logging.getLogger(__name__)
app = BedrockAgentCoreApp()

_agent = None


def _extract_user_claims(context):
    """Decode the interceptor-forwarded user token for OBO. Signature is NOT
    re-validated — the REQUEST interceptor already validated the user JWT before
    injecting these headers.

    Prefers the interceptor-injected ``X-User-Authorization`` (the verified user
    token). Falls back to ``Authorization`` for local/direct testing, though in
    the deployed path ``Authorization`` carries the Gateway's M2M token, not the
    user's."""
    try:
        request_headers = getattr(context, "request_headers", None) or {}
        verified_sub = request_headers.get("X-Verified-User-Sub") or request_headers.get("x-verified-user-sub")
        auth_header = (
            request_headers.get("X-User-Authorization")
            or request_headers.get("x-user-authorization")
            or request_headers.get("Authorization")
            or request_headers.get("authorization")
        )
        if not auth_header:
            if verified_sub:
                logger.info("OBO identity (header only): sub=%s", verified_sub)
            return None
        token = auth_header[7:] if auth_header.startswith("Bearer ") else auth_header
        claims = jwt.decode(token, options={"verify_signature": False})
        logger.info("OBO claims: sub=%s (verified header sub=%s)", claims.get("sub"), verified_sub)
        return claims
    except jwt.InvalidTokenError as e:
        logger.warning("Could not decode forwarded user token: %s", e)
        return None


def _get_agent():
    global _agent
    if _agent is None:
        logger.info("Initializing strands agent...")
        from strands import Agent
        from strands.models.bedrock import BedrockModel

        guardrail_config = {}
        guardrail_id = os.environ.get("GUARDRAIL_ID")
        guardrail_version = os.environ.get("GUARDRAIL_VERSION")
        if guardrail_id and guardrail_version:
            guardrail_config = {
                "guardrail_id": guardrail_id,
                "guardrail_version": guardrail_version,
                "guardrail_trace": "enabled",
            }
            logger.info("Guardrail enabled: %s v%s", guardrail_id, guardrail_version)

        model = BedrockModel(
            model_id=os.environ.get("MODEL_ID", "global.amazon.nova-2-lite-v1:0"),
            region_name=os.environ.get("AWS_REGION", "us-west-2"),
            max_tokens=4096,
            **guardrail_config,
        )
        _agent = Agent(
            model=model,
            system_prompt=(
                "You are a helpful assistant deployed on Amazon Bedrock AgentCore Runtime. "
                "You are part of a security reference architecture that demonstrates "
                "defense-in-depth security controls including session binding, "
                "gateway-enforced access control, and prompt-layer guardrails. "
                "Answer questions concisely and helpfully."
            ),
            callback_handler=None,
        )
        logger.info("Agent initialized successfully")
    return _agent


@app.entrypoint
async def handler(event, context):
    """AgentCore Runtime entry point with streaming support."""
    logger.info("Handler invoked with event: %s", event)
    try:
        # OBO hook: identity of the authenticated caller (from the passed-through JWT).
        _extract_user_claims(context)

        # Support both {"prompt": "..."} and the gateway/runtime {"input": {"prompt": "..."}} shapes.
        prompt = event.get("prompt")
        if prompt is None and isinstance(event.get("input"), dict):
            prompt = event["input"].get("prompt")
        prompt = prompt or "Hello!"

        agent = _get_agent()
        agent_stream = agent.stream_async(prompt)

        async for chunk in agent_stream:
            yield chunk
    except Exception as e:
        logger.exception("Handler failed: %s", e)
        yield {"error": str(e)}


if __name__ == "__main__":
    app.run()
