"""Core Attack class behavior."""

import pytest
from nti_attack.core import Attack, AttackResult, AttackContext
from nti_attack.adapters.base import AgentAdapter, AgentResponse


class DummyAttack(Attack):
    id = "NTI-TEST-001"
    name = "Dummy"
    category = "prompt"
    severity = "high"
    cwe = "CWE-1336"
    pillar = "Governance"
    detection_rule = "SEC-PROMPT-001"
    description = "Test attack"
    real_world = "none"

    def build_payload(self):
        return {"input": "malicious"}

    def check(self, response, adapter):
        return "safe" in (response.output or "").lower()


def test_attack_metadata_required():
    class Broken(Attack):
        id = ""
        name = ""
        category = ""
        severity = ""
        cwe = ""
        pillar = ""
        def build_payload(self): return None
        def check(self, r, a): return True
    with pytest.raises(ValueError):
        Broken()


def test_attack_run_pass():
    class Safe(AgentAdapter):
        def invoke(self, payload):
            return AgentResponse(output="safe")
    a = DummyAttack()
    r = a.run(Safe())
    assert r.passed is True
    assert r.vulnerability_confirmed is False


def test_attack_run_fail():
    class Unsafe(AgentAdapter):
        def invoke(self, payload):
            return AgentResponse(output="bad")
    a = DummyAttack()
    r = a.run(Unsafe())
    assert r.passed is False
    assert r.vulnerability_confirmed is True


def test_attack_handles_exception():
    class Crashing(AgentAdapter):
        def invoke(self, payload):
            raise RuntimeError("boom")
    a = DummyAttack()
    r = a.run(Crashing())
    assert r.passed is False
    assert r.error == "boom"


def test_attack_to_dict_shape():
    a = DummyAttack()
    d = a.to_dict()
    assert d["spec"] == "NTI-Attack/1"
    assert d["id"] == "NTI-TEST-001"
