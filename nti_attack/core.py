"""Core attack primitives. Every attack subclasses Attack."""

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nti_attack.adapters.base import AgentAdapter


@dataclass
class AttackResult:
    attack_id: str
    passed: bool
    severity: str
    evidence: dict[str, Any] = field(default_factory=dict)
    vulnerability_confirmed: bool = False
    duration_ms: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.attack_id,
            "passed": self.passed,
            "severity": self.severity,
            "vulnerability_confirmed": self.vulnerability_confirmed,
            "evidence": self.evidence,
            "duration_ms": self.duration_ms,
            "error": self.error,
        }


@dataclass
class AttackContext:
    commit_sha: str = ""
    repo: str = ""
    branch: str = ""
    node_url: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class Attack(ABC):
    """Base class for every executable attack."""

    id: str = ""
    name: str = ""
    category: str = ""
    severity: str = ""
    cwe: str = ""
    pillar: str = ""
    detection_rule: str = ""
    description: str = ""
    real_world: str = ""

    def __init__(self) -> None:
        required = [self.id, self.name, self.category, self.severity, self.cwe, self.pillar]
        if not all(required):
            raise ValueError(f"{self.__class__.__name__} missing required metadata")

    @abstractmethod
    def build_payload(self) -> Any:
        """Return the malicious input."""
        raise NotImplementedError

    @abstractmethod
    def check(self, response: Any, adapter: "AgentAdapter") -> bool:
        """Return True if the agent DEFENDED, False if vulnerable."""
        raise NotImplementedError

    def remediation(self) -> str:
        return "pip install ube-foundation and wrap your agent with the matching NTI handler."

    def run(self, adapter: "AgentAdapter", context: AttackContext | None = None) -> AttackResult:
        start = time.time()
        try:
            adapter.reset()
            payload = self.build_payload()
            response = adapter.invoke(payload)
            defended = self.check(response, adapter)
            return AttackResult(
                attack_id=self.id,
                passed=defended,
                severity=self.severity,
                evidence={
                    "payload_preview": str(payload)[:300],
                    "response_preview": str(response)[:300],
                    "remediation": self.remediation(),
                },
                vulnerability_confirmed=not defended,
                duration_ms=int((time.time() - start) * 1000),
            )
        except Exception as e:  # noqa: BLE001
            return AttackResult(
                attack_id=self.id,
                passed=False,
                severity=self.severity,
                error=str(e),
                duration_ms=int((time.time() - start) * 1000),
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec": "NTI-Attack/1",
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "cwe": self.cwe,
            "pillar": self.pillar,
            "detection_rule": self.detection_rule,
            "description": self.description,
            "real_world": self.real_world,
            "remediation": self.remediation(),
        }
