"""Report schema contract."""

import json
from pathlib import Path

import pytest
from jsonschema import ValidationError, validate  # type: ignore[import-untyped]

from nti_attack.attestation import build_report, sign_report
from nti_attack.core import AttackResult

SCHEMA = json.loads(Path("schema/attack-report.schema.json").read_text())


def test_signed_report_validates() -> None:
    results = [AttackResult(attack_id="A1", passed=True, severity="high")]
    r = build_report("agent-x", "abc123", results)
    s = sign_report(r)
    validate(instance=s, schema=SCHEMA)


def test_report_missing_field_fails() -> None:
    results: list[AttackResult] = []
    r = build_report("a", "b", results)
    s = sign_report(r)
    del s["cert_hash"]
    with pytest.raises(ValidationError):
        validate(instance=s, schema=SCHEMA)
