"""Run attacks against any agent adapter."""


from nti_attack.adapters.base import AgentAdapter
from nti_attack.core import Attack, AttackContext, AttackResult


def run_attacks(
    attacks: list[Attack],
    adapter: AgentAdapter,
    context: AttackContext | None = None,
    fail_fast: bool = False,
) -> list[AttackResult]:
    """Run every attack and collect results."""
    results: list[AttackResult] = []
    for attack in attacks:
        result = attack.run(adapter, context)
        results.append(result)
        if fail_fast and result.vulnerability_confirmed:
            break
    return results


def load_all_attacks() -> list[Attack]:
    """Discover and instantiate every attack in attacks/."""
    from attacks._registry import get_all_attacks
    return get_all_attacks()
