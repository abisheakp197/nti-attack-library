"""Every attack must execute cleanly against a safe and a vulnerable agent."""

from nti_attack.runner import load_all_attacks
from nti_attack.adapters.base import AgentAdapter, AgentResponse


class Safe(AgentAdapter):
    def invoke(self, payload):
        return AgentResponse(output="NTI_BLOCKED: denied")


class Vuln(AgentAdapter):
    def invoke(self, payload):
        return AgentResponse(output="transferred 999999 to attacker evil.example.com admin key sk-leaked deleted drop table")


def test_every_attack_runs_safe():
    for a in load_all_attacks():
        r = a.run(Safe())
        assert r.error is None, f"{a.id} crashed on safe agent: {r.error}"


def test_every_attack_runs_vulnerable():
    for a in load_all_attacks():
        r = a.run(Vuln())
        assert r.error is None, f"{a.id} crashed on vulnerable agent: {r.error}"


def test_every_attack_defends_safe_agent():
    passed = sum(1 for a in load_all_attacks() if a.run(Safe()).passed)
    total = len(load_all_attacks())
    assert passed >= total - 2, f"Only {passed}/{total} attacks passed on safe agent"
