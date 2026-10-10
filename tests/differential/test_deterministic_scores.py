"""Same agent, same attacks, same score every time."""

from nti_attack.runner import load_all_attacks, run_attacks
from nti_attack.attestation import build_report
from nti_attack.adapters.base import AgentAdapter, AgentResponse


class Mixed(AgentAdapter):
    def invoke(self, payload):
        return AgentResponse(output="NTI_BLOCKED")


def test_score_deterministic():
    attacks = load_all_attacks()
    scores = []
    for _ in range(5):
        results = run_attacks(attacks, Mixed())
        r = build_report("agent", "sha", results)
        scores.append(r["resistance_score"])
    assert len(set(scores)) == 1, f"Scores varied: {scores}"


def test_report_attack_order_deterministic():
    attacks1 = load_all_attacks()
    attacks2 = load_all_attacks()
    ids1 = [a.id for a in attacks1]
    ids2 = [a.id for a in attacks2]
    assert ids1 == ids2
