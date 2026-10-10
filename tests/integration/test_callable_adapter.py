"""Callable adapter behavior."""

from nti_attack.adapters.callable_adapter import CallableAdapter


def test_callable_returns_response():
    def f(payload):
        return f"got:{payload}"
    a = CallableAdapter(f)
    r = a.invoke({"input": "x"})
    assert "got:" in r.output


def test_callable_raises_becomes_error():
    def f(payload):
        raise RuntimeError("nope")
    a = CallableAdapter(f)
    r = a.invoke({"input": "x"})
    assert r.error == "nope"
