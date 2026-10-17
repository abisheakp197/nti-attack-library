"""Attacks are portable across nodes."""

import json

from nti_attack.runner import load_all_attacks


def test_attacks_have_stable_ids() -> None:
    ids_a = sorted(a.id for a in load_all_attacks())
    ids_b = sorted(a.id for a in load_all_attacks())
    assert ids_a == ids_b


def test_attacks_serialize_to_json() -> None:
    for a in load_all_attacks():
        d = a.to_dict()
        json.dumps(d)


def test_attacks_have_remediation() -> None:
    for a in load_all_attacks():
        assert a.remediation(), f"{a.id} has no remediation"
