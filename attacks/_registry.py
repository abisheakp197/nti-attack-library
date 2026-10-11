"""Discovers and instantiates every attack in this package."""

import importlib
import logging
import pkgutil
from typing import List

from nti_attack.core import Attack

logger = logging.getLogger(__name__)


def _iter_attack_classes():
    import attacks
    for _, modname, _ in pkgutil.walk_packages(attacks.__path__, prefix="attacks."):
        if modname.endswith("._registry") or modname.endswith(".__init__"):
            continue
        try:
            mod = importlib.import_module(modname)
        except (ImportError, AttributeError, TypeError) as e:
            logger.warning("Failed to import module %s: %s", modname, e)
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
        except (ImportError, AttributeError, TypeError) as e:
            logger.warning("Failed to instantiate attack %s: %s", cls, e)
            continue
    return sorted(instances, key=lambda a: a.id)
