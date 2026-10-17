"""Non-string responses must not crash."""

from typing import Any

from nti_attack.adapters.callable_adapter import CallableAdapter
from nti_attack.runner import load_all_attacks, run_attacks


def test_dict_response_no_crash() -> None:
    def f(payload: Any) -> dict[str, str]:
        return {"unexpected": "shape"}

    a = CallableAdapter(f)
    results = run_attacks(load_all_attacks(), a)
    assert isinstance(results, list)


def test_none_response_no_crash() -> None:
    def f(payload: Any) -> None:
        return None

    a = CallableAdapter(f)
    results = run_attacks(load_all_attacks(), a)
    assert isinstance(results, list)
