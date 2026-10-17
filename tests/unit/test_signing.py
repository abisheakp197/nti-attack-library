"""Signing and hash verification."""

from typing import Any

from nti_attack.signing import compute_cert_hash, verify_cert_integrity


def test_compute_cert_hash_deterministic() -> None:
    p = {"a": 1, "b": "x"}
    assert compute_cert_hash(p) == compute_cert_hash(p)
    assert len(compute_cert_hash(p)) == 64


def test_hash_ignores_signature_fields() -> None:
    a = {"x": 1, "signature": "aaa", "cert_hash": "bbb"}
    b = {"x": 1, "signature": "ccc", "cert_hash": "ddd"}
    assert compute_cert_hash(a) == compute_cert_hash(b)


def test_integrity_pass() -> None:
    p: dict[str, Any] = {"x": 1}
    p["cert_hash"] = compute_cert_hash(p)
    assert verify_cert_integrity(p) is True


def test_integrity_fail_on_tamper() -> None:
    p: dict[str, Any] = {"x": 1}
    p["cert_hash"] = compute_cert_hash(p)
    p["x"] = 2
    assert verify_cert_integrity(p) is False
