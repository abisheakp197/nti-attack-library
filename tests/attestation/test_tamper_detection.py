"""Tampered reports must fail verification."""

from nti_attack.attestation import build_report, sign_report, verify_report
from nti_attack.core import AttackResult


def test_score_tamper_detected() -> None:
    results = [AttackResult(attack_id="A1", passed=True, severity="high")]
    r = build_report("agent-x", "abc123", results)
    s = sign_report(r)
    s["resistance_score"] = 0
    v = verify_report(s)
    assert v["ok"] is False


def test_agent_id_tamper_detected() -> None:
    results = [AttackResult(attack_id="A1", passed=True, severity="high")]
    r = build_report("agent-x", "abc123", results)
    s = sign_report(r)
    s["agent_id"] = "attacker-agent"
    v = verify_report(s)
    assert v["ok"] is False


def test_commit_tamper_detected() -> None:
    results = [AttackResult(attack_id="A1", passed=True, severity="high")]
    r = build_report("agent-x", "abc123", results)
    s = sign_report(r)
    s["commit_sha"] = "ffffffff"
    v = verify_report(s)
    assert v["ok"] is False
