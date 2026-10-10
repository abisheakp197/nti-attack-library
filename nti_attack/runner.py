"""Run attacks against any agent adapter."""

from typing import List, Optional

from nti_attack.core import Attack, AttackContext, AttackResult
from nti_attack.adapters.base import AgentAdapter


def run_attacks(
    attacks: List[Attack],
    adapter: AgentAdapter,
    context: Optional[AttackContext] = None,
    fail_fast: bool = False,
) -> List[AttackResult]:
    """Run every attack and collect results."""
    results = []
    for attack in attacks:
        result = attack.run(adapter, context)
        results.append(result)
        if fail_fast and result.vulnerability_confirmed:
            break
    return results


def load_all_attacks() -> List[Attack]:
    """Discover and instantiate every attack in attacks/."""
    from attacks._registry import get_all_attacks
    return get_all_attacks()
