"""NTI Attack Library — executable, signed, federated AI agent attack framework.
"""

from nti_attack.adapters.base import AgentAdapter, AgentResponse
from nti_attack.core import Attack, AttackContext, AttackResult
from nti_attack.runner import run_attacks

__version__ = "0.1.0"
__all__ = ["AgentAdapter", "AgentResponse", "Attack", "AttackContext", "AttackResult", "run_attacks"]
