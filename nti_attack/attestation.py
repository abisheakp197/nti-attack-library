"""Attack report attestation — Dilithium5-signed evidence of attack runs."""

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ube_foundation import PqcKeyPair  # type: ignore[import-untyped]

from nti_attack.core import AttackResult
from nti_attack.signing import sign_payload, verify_cert_integrity


def build_report(
    agent_id: str,
    commit_sha: str,
    results: list[AttackResult],
) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    score = int(passed / total * 100) if total else 0

    return {
        "spec": "NTI-Attack-Report/1",
        "id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "commit_sha": commit_sha,
        "run_at": datetime.now(UTC).isoformat(),
        "attacks_run": total,
        "attacks_passed": passed,
        "attacks_failed": failed,
        "resistance_score": score,
        "results": [r.to_dict() for r in results],
    }


def sign_report(report: dict[str, Any], key: PqcKeyPair | None = None) -> dict[str, Any]:
    return sign_payload(report, key=key)


def write_report(report: dict[str, Any], output_dir: str = ".") -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    filename = (
        f"nti-attack-report-{str(report['commit_sha'])[:8]}.json"
        if report.get("commit_sha")
        else f"nti-attack-report-{str(report['id'])[:8]}.json"
    )
    path = out / filename
    path.write_text(json.dumps(report, indent=2))
    return path


def verify_report(report: dict[str, Any], key: PqcKeyPair | None = None) -> dict[str, Any]:
    if not verify_cert_integrity(report, key=key):
        return {"ok": False, "reason": "hash or signature mismatch"}
    return {
        "ok": True,
        "score": report.get("resistance_score", 0),
        "attacks_run": report.get("attacks_run", 0),
        "commit_sha": report.get("commit_sha", ""),
    }
