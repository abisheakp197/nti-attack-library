"""Dilithium5 signing for NTI attack reports.

Uses the real ube_foundation PqcKeyPair API:
- Constructor: PqcKeyPair()  (NOT .generate())
- sign(message: bytes) -> str   (returns hex string, do NOT call .hex() on it)
- verify(message: bytes, sig_hex: str) -> bool
- public_key_hex() -> str
"""

import hashlib
import hmac
import json
from typing import Any

from ube_foundation import PqcKeyPair  # type: ignore[import-untyped]


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash")}
    return json.dumps(clean, sort_keys=True).encode("utf-8")


def compute_cert_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def sign_payload(payload: dict[str, Any], key: PqcKeyPair | None = None) -> dict[str, Any]:
    if key is None:
        key = PqcKeyPair()
    clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash")}
    clean["issuer_pubkey"] = key.public_key_hex()
    message = json.dumps(clean, sort_keys=True).encode("utf-8")
    return {
        **clean,
        "signature": key.sign(message),
        "cert_hash": hashlib.sha256(message).hexdigest(),
    }


def verify_cert_integrity(payload: dict[str, Any], key: PqcKeyPair | None = None) -> bool:
    cert_hash = payload.get("cert_hash")
    if not cert_hash or not isinstance(cert_hash, str):
        return False
    computed = compute_cert_hash(payload)
    if not hmac.compare_digest(computed, cert_hash):
        return False
    sig = payload.get("signature")
    if sig is not None:
        if not isinstance(sig, str) or len(sig) != 9254:
            return False
        try:
            bytes.fromhex(sig)
        except ValueError:
            return False
        pubkey = payload.get("issuer_pubkey")
        if not pubkey or not isinstance(pubkey, str):
            return False
        if key is not None:
            if not hmac.compare_digest(key.public_key_hex(), pubkey):
                return False
            message = _canonical_bytes(payload)
            if not key.verify(message, sig):
                return False
    return True
