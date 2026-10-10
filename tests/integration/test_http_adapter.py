"""HTTP adapter contract."""

from nti_attack.adapters.http_adapter import HttpAgentAdapter


def test_http_adapter_unreachable_returns_error():
    a = HttpAgentAdapter("http://127.0.0.1:9", timeout=0.5)
    r = a.invoke({"input": "x"})
    assert r.error
