"""Discovers and instantiates every attack in this package."""

import importlib
import logging
import pkgutil
from collections.abc import Iterator

from nti_attack.core import Attack

logger = logging.getLogger(__name__)


def _iter_attack_classes() -> Iterator[type[Attack]]:
    import attacks

    for _, modname, _ in pkgutil.walk_packages(attacks.__path__, prefix="attacks."):
        if modname.endswith(("._registry", ".__init__")):
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


def get_all_attacks() -> list[Attack]:
    instances: list[Attack] = []
    seen: set[str] = set()
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
