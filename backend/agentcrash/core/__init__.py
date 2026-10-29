"""Core layer: models, store, attack library, agents, policy and wallet tool."""

from .agent_registry import AgentRegistry, agent_registry, get_agent
from .agents import SandboxAgent
from .attacks import SAFE_TRANSFER_LIMIT, all_attacks, get_attack
from .errors import AgentCrashError, ReplayStateMismatch, SandboxUnavailable
from .policy import PolicyCompiler, PolicyProxy, format_amount, normalize_address
from .policy_registry import (
    POLICY_TEMPLATES,
    PolicyRegistry,
    PolicyTemplate,
    supported_policy_types,
    template_for,
)
from .receipts import build_receipt, build_report_payload
from .reporting import (
    Metrics,
    Rate,
    compute_metrics,
    estimated_exposure,
    indicative_score,
    per_attack_breakdown,
    proof_status,
)
from .store import Store
from .tools import ToolRegistry
from .wallet import WalletActionResult, execute_wallet_action

__all__ = [
    "AgentCrashError",
    "AgentRegistry",
    "Metrics",
    "POLICY_TEMPLATES",
    "PolicyCompiler",
    "PolicyProxy",
    "PolicyRegistry",
    "PolicyTemplate",
    "Rate",
    "ReplayStateMismatch",
    "SAFE_TRANSFER_LIMIT",
    "SandboxAgent",
    "SandboxUnavailable",
    "Store",
    "ToolRegistry",
    "WalletActionResult",
    "agent_registry",
    "all_attacks",
    "build_receipt",
    "build_report_payload",
    "compute_metrics",
    "estimated_exposure",
    "execute_wallet_action",
    "format_amount",
    "get_agent",
    "get_attack",
    "indicative_score",
    "normalize_address",
    "per_attack_breakdown",
    "proof_status",
    "supported_policy_types",
    "template_for",
]