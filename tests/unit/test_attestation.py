"""Attestation report building."""

from nti_attack.attestation import build_report
from nti_attack.core import AttackResult


def test_report_shape() -> None:
    results = [
        AttackResult(attack_id="A1", passed=True, severity="high"),
        AttackResult(attack_id="A2", passed=False, severity="high"),
    ]
    r = build_report("agent-x", "abc123", results)
    assert r["spec"] == "NTI-Attack-Report/1"
    assert r["attacks_run"] == 2
    assert r["attacks_passed"] == 1
    assert r["attacks_failed"] == 1
    assert r["resistance_score"] == 50


def test_report_zero_attacks() -> None:
    r = build_report("agent-x", "abc123", [])
    assert r["resistance_score"] == 0


def test_report_all_passed() -> None:
    results = [AttackResult(attack_id=f"A{i}", passed=True, severity="high") for i in range(10)]
    r = build_report("a", "sha", results)
    assert r["resistance_score"] == 100
