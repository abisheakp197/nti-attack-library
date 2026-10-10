"""Forged signatures must fail verification."""

from nti_attack.attestation import build_report, sign_report, verify_report
from nti_attack.core import AttackResult


def test_forged_signature_fails():
    results = [AttackResult(attack_id="A1", passed=True, severity="high")]
    r = build_report("agent-x", "abc123", results)
    s = sign_report(r)
    s["cert_hash"] = "ff" * 32
    v = verify_report(s)
    assert v["ok"] is False
