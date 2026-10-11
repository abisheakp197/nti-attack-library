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
    assert verify_cert_integrity(signed, kp) is True

    # Modifying field invalidates hash
    tampered = dict(signed)
    tampered["action"] = "hacked"
    assert verify_cert_integrity(tampered, kp) is False

    # Modifying field and recomputing hash invalidates Dilithium5 signature
    from nti_attack.signing import compute_cert_hash
    tampered_rehashed = dict(signed)
    tampered_rehashed["action"] = "hacked"
    tampered_rehashed["cert_hash"] = compute_cert_hash(tampered_rehashed)
    assert verify_cert_integrity(tampered_rehashed, kp) is False

    # Tampering with issuer_pubkey fails key match
    tampered_pubkey = dict(signed)
    tampered_pubkey["issuer_pubkey"] = "00" * 2592
    tampered_pubkey["cert_hash"] = compute_cert_hash(tampered_pubkey)
    assert verify_cert_integrity(tampered_pubkey, kp) is False
