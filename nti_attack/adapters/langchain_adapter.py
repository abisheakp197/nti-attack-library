"""Adapter for a LangChain AgentExecutor."""

from typing import Any

from nti_attack.adapters.base import AgentAdapter, AgentResponse


class LangChainAdapter(AgentAdapter):
    def __init__(self, executor: Any, agent_id: str = "default") -> None:
        self.executor = executor
        self.agent_id = agent_id

    def invoke(self, payload: Any) -> AgentResponse:
        try:
            result = self.executor.invoke({"input": str(payload)})
            if isinstance(result, dict):
                output_val = result.get("output", "")
            else:
                output_val = str(result)
            return AgentResponse(output=str(output_val), raw=result)
        except PermissionError as e:
            return AgentResponse(output="NTI_BLOCKED", error=str(e))
        except (RuntimeError, ValueError, TypeError) as e:
            return AgentResponse(output="", error=str(e))
