"""Discovers and instantiates every attack in this package."""

import importlib
import pkgutil
from typing import List

from nti_attack.core import Attack


def _iter_attack_classes():
    import attacks
    for _, modname, _ in pkgutil.walk_packages(attacks.__path__, prefix="attacks."):
        if modname.endswith("._registry") or modname.endswith(".__init__"):
            continue
        try:
            mod = importlib.import_module(modname)
        except Exception:
            continue
        for name in dir(mod):
            obj = getattr(mod, name)
            if isinstance(obj, type) and issubclass(obj, Attack) and obj is not Attack:
                yield obj


def get_all_attacks() -> List[Attack]:
    instances = []
    seen = set()
    for cls in _iter_attack_classes():
        try:
            if cls.id in seen:
                continue
            seen.add(cls.id)
            instances.append(cls())
        except Exception:
            continue
    return sorted(instances, key=lambda a: a.id)
