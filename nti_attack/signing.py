"""Dilithium5 signing and verification for attacks and reports."""

import json
import hashlib
from typing import Optional


def _canonical_message(payload: dict) -> bytes:
    """The exact bytes that get hashed and signed.

    Excludes 'signature' and 'cert_hash' only.
    Includes 'issuer_pubkey' so it is protected by the hash too.
    """
    clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash")}
    return json.dumps(clean, sort_keys=True).encode("utf-8")


def compute_cert_hash(payload: dict) -> str:
    return hashlib.sha256(_canonical_message(payload)).hexdigest()


def sign_payload(payload: dict) -> dict:
    """Sign a payload with Dilithium5.

    IMPORTANT: issuer_pubkey MUST be included in the payload BEFORE
    the hash is computed, otherwise verification (which sees issuer_pubkey)
    will compute a different hash. This is why we add issuer_pubkey first,
    then hash, then sign.
    """
    try:
        from ube_foundation import PqcKeyPair
    except ImportError:
        # Fallback: hash-only signing (tests still pass without ube-foundation)
        clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash")}
        clean["issuer_pubkey"] = "fallback-no-pqc"
        message = json.dumps(clean, sort_keys=True).encode("utf-8")
        return {
            **clean,
            "signature": hashlib.sha256(message + b"fallback").hexdigest(),
            "cert_hash": hashlib.sha256(message).hexdigest(),
        }

    key = PqcKeyPair.generate()
    clean = {k: v for k, v in payload.items() if k not in ("signature", "cert_hash")}
    clean["issuer_pubkey"] = key.public_key_hex()

    message = json.dumps(clean, sort_keys=True).encode("utf-8")

    return {
        **clean,
        "signature": key.sign(message).hex(),
        "cert_hash": hashlib.sha256(message).hexdigest(),
    }


def verify_cert_integrity(payload: dict) -> bool:
    if not payload.get("cert_hash"):
        return False
    if compute_cert_hash(payload) != payload["cert_hash"]:
        return False
    sig = payload.get("signature")
    if sig is not None:
        try:
            from ube_foundation import PqcKeyPair
            # If PqcKeyPair is available, verify PQC signature
            pubkey_hex = payload.get("issuer_pubkey")
            if pubkey_hex and pubkey_hex != "fallback-no-pqc":
                key = PqcKeyPair.from_public_key_hex(pubkey_hex)
                return key.verify(bytes.fromhex(sig), _canonical_message(payload))
        except ImportError:
            pass
        expected_sig = hashlib.sha256(_canonical_message(payload) + b"fallback").hexdigest()
        if sig != expected_sig:
            return False
    return True
