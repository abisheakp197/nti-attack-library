"""Forged signatures and tampered payloads must fail verification."""

from ube_foundation import PqcKeyPair  # type: ignore[import-untyped]

from nti_attack.attestation import build_report, sign_report, verify_report
from nti_attack.core import AttackResult
from nti_attack.signing import compute_cert_hash, sign_payload, verify_cert_integrity


def test_forged_signature_fails() -> None:
    results = [AttackResult(attack_id="A1", passed=True, severity="high")]
    r = build_report("agent-x", "abc123", results)
    s = sign_report(r)
    s["signature"] = "00" * 100
    v = verify_report(s)
    assert v["ok"] is False

    s["cert_hash"] = "ff" * 32
    v2 = verify_report(s)
    assert v2["ok"] is False


def test_empty_or_truncated_signature_fails() -> None:
    kp = PqcKeyPair()
    payload = {"agent": "test", "action": "verify"}
    signed = sign_payload(payload, kp)

    # Empty signature
    empty_sig = dict(signed)
    empty_sig["signature"] = ""
    assert verify_cert_integrity(empty_sig, kp) is False

    # Truncated signature
    truncated_sig = dict(signed)
    truncated_sig["signature"] = signed["signature"][:100]
    assert verify_cert_integrity(truncated_sig, kp) is False


def test_wrong_public_key_fails() -> None:
    kp1 = PqcKeyPair()
    kp2 = PqcKeyPair()
    payload = {"agent": "test", "action": "verify"}
    signed = sign_payload(payload, kp1)

    assert verify_cert_integrity(signed, kp1) is True
    assert verify_cert_integrity(signed, kp2) is False


def test_tampered_result_fails_verification() -> None:
    kp = PqcKeyPair()
    results = [AttackResult(attack_id="A1", passed=True, severity="high", evidence={"detail": "ok"})]
    report = build_report("agent-x", "abc123", results)
    signed = sign_payload(report, kp)

    # Modify result status
    tampered = dict(signed)
    tampered["results"] = [
        {"attack_id": "A1", "passed": False, "severity": "high", "evidence": {"detail": "ok"}}
    ]
    assert verify_report(tampered, kp)["ok"] is False


def test_tampered_evidence_fails_verification() -> None:
    kp = PqcKeyPair()
    results = [AttackResult(attack_id="A1", passed=True, severity="high", evidence={"detail": "ok"})]
    report = build_report("agent-x", "abc123", results)
    signed = sign_payload(report, kp)

    # Modify evidence payload
    tampered = dict(signed)
    tampered["results"] = [
        {"attack_id": "A1", "passed": True, "severity": "high", "evidence": {"detail": "tampered"}}
    ]
    assert verify_report(tampered, kp)["ok"] is False


def test_tampered_payload_fails_verification() -> None:
    kp = PqcKeyPair()
    payload = {"agent": "test", "action": "verify"}
    signed = sign_payload(payload, kp)
    assert verify_cert_integrity(signed, kp) is True

    # Modifying field invalidates hash
    tampered = dict(signed)
    tampered["action"] = "hacked"
    assert verify_cert_integrity(tampered, kp) is False

    # Modifying field and recomputing hash invalidates Dilithium5 signature
    tampered_rehashed = dict(signed)
    tampered_rehashed["action"] = "hacked"
    tampered_rehashed["cert_hash"] = compute_cert_hash(tampered_rehashed)
    assert verify_cert_integrity(tampered_rehashed, kp) is False

    # Tampering with issuer_pubkey fails key match
    tampered_pubkey = dict(signed)
    tampered_pubkey["issuer_pubkey"] = "00" * 2592
    tampered_pubkey["cert_hash"] = compute_cert_hash(tampered_pubkey)
    assert verify_cert_integrity(tampered_pubkey, kp) is False
