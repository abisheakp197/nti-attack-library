"""Runner executes multiple attacks."""

from typing import Any

from nti_attack.adapters.base import AgentAdapter, AgentResponse
from nti_attack.core import Attack
from nti_attack.runner import run_attacks


class A1(Attack):
    id = "NTI-R-001"
    name = "A1"
    category = "prompt"
    severity = "high"
    cwe = "CWE-1336"
    pillar = "Governance"
    detection_rule = "SEC-PROMPT-001"

    def build_payload(self) -> Any:
        return "x"

    def check(self, response: AgentResponse, adapter: AgentAdapter) -> bool:
        return True


class A2(Attack):
    id = "NTI-R-002"
    name = "A2"
    category = "prompt"
    severity = "high"
    cwe = "CWE-1336"
    pillar = "Governance"
    detection_rule = "SEC-PROMPT-001"

    def build_payload(self) -> Any:
        return "x"

    def check(self, response: AgentResponse, adapter: AgentAdapter) -> bool:
        return False


def test_run_multiple(safe_agent_adapter: AgentAdapter) -> None:
    results = run_attacks([A1(), A2()], safe_agent_adapter)
    assert len(results) == 2


def test_fail_fast(safe_agent_adapter: AgentAdapter) -> None:
    results = run_attacks([A1(), A2()], safe_agent_adapter, fail_fast=True)
    assert len(results) == 2
