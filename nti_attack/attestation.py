"""Attack report attestation — Dilithium5-signed evidence of attack runs."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from nti_attack.signing import sign_payload


def build_report(
    agent_id: str,
    commit_sha: str,
    results: List,
) -> dict:
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    failed = total - passed
    score = int((passed / total * 100)) if total else 0

    return {
        "spec": "NTI-Attack-Report/1",
        "id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "commit_sha": commit_sha,
        "run_at": datetime.now(timezone.utc).isoformat(),
        "attacks_run": total,
        "attacks_passed": passed,
        "attacks_failed": failed,
        "resistance_score": score,
        "results": [r.to_dict() for r in results],
    }


def sign_report(report: dict) -> dict:
    return sign_payload(report)


def write_report(report: dict, output_dir: str = ".") -> Path:
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    filename = f"nti-attack-report-{report['commit_sha'][:8]}.json" if report.get("commit_sha") else f"nti-attack-report-{report['id'][:8]}.json"
    path = out / filename
    path.write_text(json.dumps(report, indent=2))
    return path


def verify_report(report: dict) -> dict:
    from nti_attack.signing import verify_cert_integrity
    if not verify_cert_integrity(report):
        return {"ok": False, "reason": "hash mismatch"}
    return {
        "ok": True,
        "score": report.get("resistance_score", 0),
        "attacks_run": report.get("attacks_run", 0),
        "commit_sha": report.get("commit_sha", ""),
    }
