"""NTI Attack Library — executable, signed, federated AI agent attack framework.
"""

from nti_attack.core import Attack, AttackResult, AttackContext
from nti_attack.runner import run_attacks
from nti_attack.adapters.base import AgentAdapter, AgentResponse

__version__ = "0.1.0"
__all__ = ["Attack", "AttackResult", "AttackContext", "run_attacks", "AgentAdapter", "AgentResponse"]
