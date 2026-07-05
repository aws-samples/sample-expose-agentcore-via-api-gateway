"""
Strands Agents agent for the AgentCore Runtime Security Sample.

This agent is deployed to Amazon Bedrock AgentCore Runtime and serves as the
backend for the security reference architecture. It is fronted by an AgentCore
Gateway that validates the caller's Cognito JWT (CUSTOM_JWT inbound), runs a
REQUEST interceptor (session binding + throttling), and forwards the request to
this runtime with the user's bearer token passed through unchanged
(JWT_PASSTHROUGH outbound).

Because the Gateway target uses JWT pass-through and the runtime is OAuth
inbound, the user's identity reaches the agent: AgentCore Identity has already
validated the token, and the Authorization header is allowlisted through to the
agent (RequestHeaderConfiguration). We decode the claims here WITHOUT
re-validating the signature — this is the on-behalf-of (OBO) hook where the
agent can act as the authenticated user.

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
    """Decode the passed-through JWT for OBO. Signature is NOT re-validated —
    AgentCore Runtime already validated it during OAuth inbound authorization."""
    try:
        request_headers = getattr(context, "request_headers", None) or {}
        auth_header = request_headers.get("Authorization") or request_headers.get("authorization")
        if not auth_header:
            return None
        token = auth_header[7:] if auth_header.startswith("Bearer ") else auth_header
        claims = jwt.decode(token, options={"verify_signature": False})
        logger.info("OBO claims: sub=%s", claims.get("sub"))
        return claims
    except jwt.InvalidTokenError as e:
        logger.warning("Could not decode passed-through JWT: %s", e)
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
