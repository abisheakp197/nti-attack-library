"""Callable adapter behavior."""

from typing import Any

from nti_attack.adapters.callable_adapter import CallableAdapter


def test_callable_returns_response() -> None:
    def f(payload: Any) -> str:
        return f"got:{payload}"

    a = CallableAdapter(f)
    r = a.invoke({"input": "x"})
    assert "got:" in r.output


def test_callable_raises_becomes_error() -> None:
    def f(payload: Any) -> str:
        raise RuntimeError("nope")

    a = CallableAdapter(f)
    r = a.invoke({"input": "x"})
    assert r.error == "nope"
