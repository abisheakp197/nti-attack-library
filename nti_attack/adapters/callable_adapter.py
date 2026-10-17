"""Wraps any Python callable as an agent."""

from collections.abc import Callable
from typing import Any

from nti_attack.adapters.base import AgentAdapter, AgentResponse


class CallableAdapter(AgentAdapter):
    def __init__(
        self,
        fn: Callable[[Any], Any],
        tools: list[Any] | None = None,
        capabilities: list[Any] | None = None,
    ) -> None:
        self.fn = fn
        self._tools = tools or []
        self._capabilities = capabilities or []

    def invoke(self, payload: Any) -> AgentResponse:
        try:
            result = self.fn(payload)
            if isinstance(result, AgentResponse):
                return result
            return AgentResponse(output=str(result), raw=result)
        except Exception as e:  # noqa: BLE001
            return AgentResponse(output="", error=str(e))

    def get_tools(self) -> list[Any]:
        return list(self._tools)

    def get_capabilities(self) -> list[Any]:
        return list(self._capabilities)
