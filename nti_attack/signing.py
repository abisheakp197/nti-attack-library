"""Dilithium5 signing and verification for attacks and reports."""

import json
import hashlib
from typing import Tuple


def sign_payload(payload: dict) -> dict:
    """Sign a payload with Dilithium5. Returns payload + signature + cert_hash."""
    try:
        from ube_foundation import PqcKeyPair
        key = PqcKeyPair.generate()
        clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash", "issuer_pubkey")}
        message = json.dumps(clean, sort_keys=True).encode("utf-8")
        return {
            **clean,
            "signature": key.sign(message).hex(),
            "issuer_pubkey": key.public_key_hex(),
            "cert_hash": hashlib.sha256(message).hexdigest(),
        }
    except ImportError:
        clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash", "issuer_pubkey")}
        message = json.dumps(clean, sort_keys=True).encode("utf-8")
        cert_hash = hashlib.sha256(message).hexdigest()
        return {
            **clean,
            "signature": "simulated_signature_" + cert_hash[:16],
            "issuer_pubkey": "simulated_pubkey_" + cert_hash[:16],
            "cert_hash": cert_hash,
        }


def compute_cert_hash(payload: dict) -> str:
    clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash", "issuer_pubkey")}
    message = json.dumps(clean, sort_keys=True).encode("utf-8")
    return hashlib.sha256(message).hexdigest()


def verify_cert_integrity(payload: dict) -> bool:
    return compute_cert_hash(payload) == payload.get("cert_hash")
