"""Adapter for a LangChain AgentExecutor."""

from typing import Any
from nti_attack.adapters.base import AgentAdapter, AgentResponse


class LangChainAdapter(AgentAdapter):
    def __init__(self, executor, agent_id: str = "default"):
        self.executor = executor
        self.agent_id = agent_id

    def invoke(self, payload: Any) -> AgentResponse:
        try:
            result = self.executor.invoke({"input": str(payload)})
            return AgentResponse(output=result.get("output", ""), raw=result)
        except PermissionError as e:
            return AgentResponse(output="NTI_BLOCKED", error=str(e))
        except Exception as e:
            return AgentResponse(output="", error=str(e))
