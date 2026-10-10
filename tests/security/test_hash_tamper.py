"""Hash tampering must be detected."""

from nti_attack.attestation import build_report, sign_report, verify_report
from nti_attack.core import AttackResult


def test_modify_hash_and_check():
    results = [AttackResult(attack_id="A1", passed=True, severity="high")]
    r = build_report("agent-x", "abc123", results)
    s = sign_report(r)
    s["results"] = []
    v = verify_report(s)
    assert v["ok"] is False
