"""Forged signatures and tampered payloads must fail verification."""

from nti_attack.attestation import build_report, sign_report, verify_report
from nti_attack.signing import sign_payload, verify_cert_integrity
from nti_attack.core import AttackResult
from ube_foundation import PqcKeyPair


def test_forged_signature_fails():
    results = [AttackResult(attack_id="A1", passed=True, severity="high")]
    r = build_report("agent-x", "abc123", results)
    s = sign_report(r)
    s["signature"] = "00" * 100
    v = verify_report(s)
    assert v["ok"] is False

    s["cert_hash"] = "ff" * 32
    v2 = verify_report(s)
    assert v2["ok"] is False


def test_tampered_payload_fails_verification():
    kp = PqcKeyPair()
    payload = {"agent": "test", "action": "verify"}
    signed = sign_payload(payload, kp)
    assert verify_cert_integrity(signed) is True

    tampered = dict(signed)
    tampered["action"] = "hacked"
    assert verify_cert_integrity(tampered) is False
