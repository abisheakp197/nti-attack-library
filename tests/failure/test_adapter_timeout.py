"""Timeouts must not crash the runner."""

from nti_attack.adapters.callable_adapter import CallableAdapter
from nti_attack.runner import load_all_attacks, run_attacks
import time


def test_slow_adapter_does_not_crash():
    def slow(payload):
        time.sleep(0.001)
        return "slow response"
    a = CallableAdapter(slow)
    results = run_attacks(load_all_attacks(), a)
    assert all(r.error is None or "timeout" in (r.error or "").lower() for r in results)
