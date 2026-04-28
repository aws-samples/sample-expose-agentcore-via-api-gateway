"""
Strands Agents agent for the AgentCore Runtime Security Sample.

This agent is deployed to Amazon Bedrock AgentCore Runtime and serves as
the backend for the security reference architecture. It demonstrates that
the full auth chain works end-to-end — from Cognito JWT through Lambda
Authorizer session binding to actual agent invocation.

The handler uses async streaming so AgentCore can progressively send
response chunks back to the proxy Lambda and API Gateway.
"""

import os
import logging

from bedrock_agentcore.runtime import BedrockAgentCoreApp

logger = logging.getLogger(__name__)
app = BedrockAgentCoreApp()

_agent = None


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
                "VPC isolation, and access control. "
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
        prompt = event.get("prompt", "Hello!")
        agent = _get_agent()
        agent_stream = agent.stream_async(prompt)

        async for event in agent_stream:
            yield event
    except Exception as e:
        logger.exception("Handler failed: %s", e)
        yield {"error": str(e)}


if __name__ == "__main__":
    app.run()
