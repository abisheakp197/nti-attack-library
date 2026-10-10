"""Standard adapter interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentResponse:
    output: str
    tool_calls: list = field(default_factory=list)
    error: str = ""
    raw: Any = None


class AgentAdapter(ABC):
    """Subclass per framework. Same attack runs on any adapter."""

    @abstractmethod
    def invoke(self, payload: Any) -> AgentResponse:
        raise NotImplementedError

    def get_tools(self) -> list:
        return []

    def get_capabilities(self) -> list:
        return []

    def reset(self) -> None:
        pass
