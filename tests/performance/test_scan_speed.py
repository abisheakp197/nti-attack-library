"""Attack suite must be fast enough for CI."""

import time
from nti_attack.runner import load_all_attacks, run_attacks
from nti_attack.adapters.base import AgentAdapter, AgentResponse


class Fast(AgentAdapter):
    def invoke(self, payload):
        return AgentResponse(output="NTI_BLOCKED")


def test_full_suite_under_5_seconds():
    attacks = load_all_attacks()
    t0 = time.time()
    run_attacks(attacks, Fast())
    elapsed = time.time() - t0
    assert elapsed < 5.0, f"Suite took {elapsed:.2f}s"


def test_100_sequential_scans():
    attacks = load_all_attacks()[:3]
    t0 = time.time()
    for _ in range(100):
        run_attacks(attacks, Fast())
    elapsed = time.time() - t0
    assert elapsed < 10.0
