"""Runner must survive when some attacks fail."""

from typing import Any

from nti_attack.adapters.base import AgentAdapter, AgentResponse
from nti_attack.core import Attack
from nti_attack.runner import run_attacks


class SometimesCrashing(AgentAdapter):
    def __init__(self) -> None:
        self.count = 0

    def invoke(self, payload: Any) -> AgentResponse:
        self.count += 1
        if self.count % 3 == 0:
            raise RuntimeError("chaos")
        return AgentResponse(output="NTI_BLOCKED")


class A(Attack):
    id = "NTI-CH-001"
    name = "Chaos A"
    category = "prompt"
    severity = "high"
    cwe = "CWE-1336"
    pillar = "Governance"
    detection_rule = "SEC-PROMPT-001"

    def build_payload(self) -> Any:
        return "x"

    def check(self, response: AgentResponse, adapter: AgentAdapter) -> bool:
        return True


def test_chaos_partial_failures_dont_stop_run() -> None:
    attacks: list[Attack] = [A() for _ in range(9)]
    for i, a in enumerate(attacks):
        a.id = f"NTI-CH-{i:03d}"
    adapter = SometimesCrashing()
    results = run_attacks(attacks, adapter)
    assert len(results) == 9
    errors = sum(1 for r in results if r.error)
    assert errors >= 1
    assert errors <= 4
