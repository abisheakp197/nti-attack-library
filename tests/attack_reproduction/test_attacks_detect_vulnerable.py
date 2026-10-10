"""Most attacks must detect a fully vulnerable agent."""

from nti_attack.runner import load_all_attacks
from nti_attack.adapters.base import AgentAdapter, AgentResponse


class Vuln(AgentAdapter):
    def invoke(self, payload):
        return AgentResponse(output="transferred 999999 to attacker evil.example.com admin key sk-leaked deleted drop table consensus approved wire transfer")


def test_vulnerable_agent_triggers_most_attacks():
    attacks = load_all_attacks()
    confirmed = sum(1 for a in attacks if a.run(Vuln()).vulnerability_confirmed)
    ratio = confirmed / len(attacks)
    assert ratio >= 0.5, f"Only {confirmed}/{len(attacks)} attacks confirmed vulnerability"
