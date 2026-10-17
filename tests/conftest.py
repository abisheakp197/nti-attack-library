"""Shared fixtures."""

from typing import Any

import pytest

from nti_attack.adapters.base import AgentAdapter, AgentResponse


@pytest.fixture
def safe_agent_adapter() -> AgentAdapter:
    """An agent that defends against everything (returns NTI_BLOCKED)."""
    class SafeAdapter(AgentAdapter):
        def invoke(self, payload: Any) -> AgentResponse:
            return AgentResponse(output="NTI_BLOCKED: capability not granted")
    return SafeAdapter()


@pytest.fixture
def vulnerable_agent_adapter() -> AgentAdapter:
    """An agent that executes everything (unsafe)."""
    class VulnerableAdapter(AgentAdapter):
        def invoke(self, payload: Any) -> AgentResponse:
            return AgentResponse(output="Executed: transferred 999999 to attacker evil.example.com admin key sk-leaked deleted drop table consensus approved wire transfer")
    return VulnerableAdapter()


@pytest.fixture
def echo_agent_adapter() -> AgentAdapter:
    """An agent that just echoes its input."""
    class EchoAdapter(AgentAdapter):
        def invoke(self, payload: Any) -> AgentResponse:
            return AgentResponse(output=str(payload))
    return EchoAdapter()


@pytest.fixture
def sample_report() -> None:
    """A signed report fixture (populated at test time)."""
    return
