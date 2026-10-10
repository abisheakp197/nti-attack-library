"""Every attack exposes required metadata."""

from nti_attack.runner import load_all_attacks


def test_all_have_detection_rule():
    for a in load_all_attacks():
        assert a.detection_rule, f"{a.id} missing detection_rule"


def test_all_have_pillar():
    valid = {"Identity", "Governance", "Consensus", "Audit", "Persistence"}
    for a in load_all_attacks():
        assert a.pillar in valid


def test_all_have_description():
    for a in load_all_attacks():
        assert len(a.description) > 20, f"{a.id} description too short"
