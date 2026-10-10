"""Signed report verifies offline."""

from nti_attack.attestation import build_report, sign_report, verify_report
from nti_attack.core import AttackResult


def test_signed_report_verifies():
    results = [AttackResult(attack_id="A1", passed=True, severity="high")]
    r = build_report("agent-x", "abc123", results)
    s = sign_report(r)
    v = verify_report(s)
    assert v["ok"] is True
    assert v["score"] == 100
    assert v["commit_sha"] == "abc123"
