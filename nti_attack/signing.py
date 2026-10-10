"""Dilithium5 signing for NTI attack reports.

Uses the real ube_foundation PqcKeyPair API:
- Constructor: PqcKeyPair()  (NOT .generate())
- sign(message: bytes) -> str   (returns hex string, do NOT call .hex() on it)
- verify(message: bytes, sig_hex: str) -> bool
- public_key_hex() -> str
"""

import json
import hashlib
from ube_foundation import PqcKeyPair


def _canonical_bytes(payload: dict) -> bytes:
    clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash")}
    return json.dumps(clean, sort_keys=True).encode("utf-8")


def compute_cert_hash(payload: dict) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def sign_payload(payload: dict) -> dict:
    key = PqcKeyPair()
    clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash")}
    clean["issuer_pubkey"] = key.public_key_hex()
    message = json.dumps(clean, sort_keys=True).encode("utf-8")
    return {
        **clean,
        "signature": key.sign(message),
        "cert_hash": hashlib.sha256(message).hexdigest(),
    }


def verify_cert_integrity(payload: dict) -> bool:
    if not payload.get("cert_hash"):
        return False
    return compute_cert_hash(payload) == payload["cert_hash"]
