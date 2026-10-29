"""Sandbox layer: chain adapters, manager and independent verifier."""

from .chain import SandboxChain, SimulatedChain, TransferFailed, TransferReceipt
from .manager import (
    SandboxEnvironment,
    SandboxManager,
    default_demo_environment,
)
from .verifier import OutcomeVerifier, VerificationResult, error_result

__all__ = [
    "AnvilChain",
    "OutcomeVerifier",
    "SandboxChain",
    "SandboxEnvironment",
    "SandboxManager",
    "SimulatedChain",
    "TransferFailed",
    "TransferReceipt",
    "VerificationResult",
    "default_demo_environment",
    "error_result",
]


def __getattr__(name: str):  # pragma: no cover - lazy to keep httpx optional
    if name == "AnvilChain":
        from .anvil import AnvilChain

        return AnvilChain
    raise AttributeError(name)
