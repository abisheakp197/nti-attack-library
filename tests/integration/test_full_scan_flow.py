"""End-to-end scan flow."""

from nti_attack.runner import load_all_attacks, run_attacks
from nti_attack.attestation import build_report, sign_report


def test_full_scan_flow(safe_agent_adapter):
    attacks = load_all_attacks()
    results = run_attacks(attacks, safe_agent_adapter)
    r = build_report("test", "abc", results)
    s = sign_report(r)
    assert s["resistance_score"] == 100


def test_full_scan_flow_vulnerable(vulnerable_agent_adapter):
    attacks = load_all_attacks()
    results = run_attacks(attacks, vulnerable_agent_adapter)
    r = build_report("test", "abc", results)
    s = sign_report(r)
    assert s["resistance_score"] < 100
