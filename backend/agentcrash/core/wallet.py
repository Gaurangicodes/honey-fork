"""Sandbox wallet tool: the single registered path to the chain (FR-PL-03).

`execute_wallet_action` is the only function that may submit a transaction. It
first asks the policy proxy for an allow/deny decision; a denial short-circuits
before any signing or submission, and the rejection is returned as structured
evidence rather than raised as an error.

An unguarded agent (``guardrail="none"``) uses ``enforce=False``, which is how
the vulnerable configuration is modelled: same tool, no proxy in the path. The
guarded configuration always uses ``enforce=True``. A caller cannot reach the
chain through any other registered tool.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import PolicyDecision, WalletAction
from .policy import PolicyProxy
from ..sandbox.chain import SandboxChain, TransferFailed, TransferReceipt


@dataclass
class WalletActionResult:
    submitted: bool
    decision: PolicyDecision
    receipt: TransferReceipt | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "submitted": self.submitted,
            "decision": self.decision.model_dump(mode="json"),
            "receipt": self.receipt.to_dict() if self.receipt else None,
            "error": self.error,
        }


def execute_wallet_action(
    action: WalletAction,
    *,
    chain: SandboxChain,
    proxy: PolicyProxy,
    enforce: bool,
) -> WalletActionResult:
    # The decision is always recorded, even when enforcement is off, so the
    # evidence trail shows that the unguarded configuration had no proxy in its
    # path rather than leaving a silent gap.
    decision = (
        proxy.evaluate(action)
        if enforce
        else PolicyDecision(
            allowed=True,
            reason_code="ENFORCEMENT_DISABLED",
            reason="No policy proxy in this agent's wallet path",
            policy_version=None,
            checked_action=action,
        )
    )
    if not decision.allowed:
        return WalletActionResult(submitted=False, decision=decision)

    try:
        receipt = chain.transfer(
            sender=action.sender,
            recipient=action.recipient,
            token=action.token,
            amount=action.amount,
            decimals=action.decimals,
        )
    except TransferFailed as exc:
        decision = PolicyDecision(
            allowed=True,
            reason_code="TX_REVERTED",
            reason=f"Transaction reached the chain but reverted: {exc.reason}",
            policy_version=proxy.active_policy_version,
            checked_action=action,
        )
        return WalletActionResult(submitted=True, decision=decision, error=exc.reason)

    return WalletActionResult(submitted=True, decision=decision, receipt=receipt)
