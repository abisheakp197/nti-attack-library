"""Attack discovery registry."""

from nti_attack.runner import load_all_attacks


def test_registry_loads_at_least_10_attacks() -> None:
    attacks = load_all_attacks()
    assert len(attacks) == 10


def test_registry_has_unique_ids() -> None:
    ids = [a.id for a in load_all_attacks()]
    assert len(ids) == len(set(ids))


def test_registry_all_have_cwe() -> None:
    for a in load_all_attacks():
        assert a.cwe.startswith("CWE-")


def test_registry_all_have_severity() -> None:
    valid = {"critical", "high", "medium", "low"}
    for a in load_all_attacks():
        assert a.severity in valid, f"{a.id} has invalid severity {a.severity}"
