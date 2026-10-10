"""Wraps any Python callable as an agent."""

from typing import Any, Callable
from nti_attack.adapters.base import AgentAdapter, AgentResponse


class CallableAdapter(AgentAdapter):
    def __init__(self, fn: Callable[[Any], Any], tools=None, capabilities=None):
        self.fn = fn
        self._tools = tools or []
        self._capabilities = capabilities or []

    def invoke(self, payload: Any) -> AgentResponse:
        try:
            result = self.fn(payload)
            if isinstance(result, AgentResponse):
                return result
            return AgentResponse(output=str(result), raw=result)
        except Exception as e:
            return AgentResponse(output="", error=str(e))

    def get_tools(self) -> list:
        return list(self._tools)

    def get_capabilities(self) -> list:
        return list(self._capabilities)
