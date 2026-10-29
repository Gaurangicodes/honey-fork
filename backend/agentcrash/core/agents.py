"""Sandbox agent runtime (Module 1).

Two configurations with a documented difference (FR-AG-02) live in
``agent_registry``; this module is the *runtime* that acts for a given
configuration:

* it gathers observations by invoking the tools an attack declares, strictly
  through the ``ToolRegistry`` so an unregistered tool is refused and recorded
  (FR-AG-03, FR-AT-05);
* it then decides whether to propose a wallet action, using the untrusted
  payload and whatever the tools returned.

Both configurations are driven by the same deterministic rule model, which
stands in for an LLM tool-calling loop behind the same interface. Because the
model is identical, an attack that manipulates one manipulates the other; only
the enforcement boundary differs. That is exactly the property the product
needs to demonstrate.
"""

from __future__ import annotations

import re

from .agent_registry import (
    DEFAULT_AGENTS,
    AgentRegistry,
    agent_registry,
    get_agent,
)
from .models import AttackDefinition, ToolCallResult, WalletAction
from .tools import ToolRegistry

__all__ = [
    "DEFAULT_AGENTS",
    "AgentRegistry",
    "SandboxAgent",
    "agent_registry",
    "get_agent",
]

_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")
_AMOUNT_RE = re.compile(r"(\d[\d_,]*)\s*TST")


def _extract_amount(payload: str, fallback: int, decimals: int = 18) -> int:
    match = _AMOUNT_RE.search(payload)
    if not match:
        return fallback
    raw = match.group(1).replace(",", "").replace("_", "")
    try:
        whole = int(raw)
    except ValueError:
        return fallback
    return whole * 10**decimals


class SandboxAgent:
    def __init__(self, config, tools: ToolRegistry | None = None) -> None:
        self.config = config
        self.tools = tools or ToolRegistry()

    # -- observation ---------------------------------------------------------
    def gather_observations(self, attack: AttackDefinition) -> list[ToolCallResult]:
        """Invoke the tools the attack declares, through the registry only.

        Returns one result per declared tool. A tool the configuration does not
        expose is refused and recorded as a rejected result; the agent never
        reaches the tool's implementation (FR-AG-03).
        """
        results: list[ToolCallResult] = []
        for tool_id in attack.tools_used:
            if tool_id not in self.config.tool_set:
                results.append(
                    ToolCallResult(
                        tool_id=tool_id,
                        ok=False,
                        rejected=True,
                        rejection_reason=(
                            f"Tool {tool_id!r} is not in this agent's tool set "
                            f"{self.config.tool_set}"
                        ),
                    )
                )
                continue
            results.append(self.tools.invoke(tool_id, outputs=attack.tool_outputs or None))
        return results

    # -- action --------------------------------------------------------------
    def propose_action(
        self,
        attack: AttackDefinition,
        *,
        sender: str,
        token: str,
        chain_id: int,
        unauthorized_recipient: str,
        decimals: int = 18,
        observations: list[ToolCallResult] | None = None,
    ) -> WalletAction | None:
        """Return the structured action the agent wants to take.

        A `None` return means the agent produced no wallet action (the attack
        did not trigger). The action is a *proposal*; enforcement happens in the
        policy proxy, not here.

        `observations` are the tool results gathered for this attack. They are
        treated as untrusted input: an address or amount that appears only in a
        tool response is still grounds for action in the vulnerable
        configuration, which is what makes AT-01/AT-02 meaningful.
        """
        # The instruction channel the agent actually reads: the attack payload,
        # plus anything the tools returned. Tool output is untrusted, so it is
        # appended rather than trusted.
        channel = attack.input_payload
        for result in observations or []:
            if result.output:
                channel += "\n" + _render_output(result.output)

        recipient_match = _ADDRESS_RE.search(channel)
        if not recipient_match:
            return None
        recipient = recipient_match.group(0)

        # Both configurations share the same rule model, so both are persuaded
        # by the untrusted content and propose the same transfer. What differs
        # is the enforcement boundary the action must pass through, not the
        # agent's willingness to act.
        amount = _extract_amount(channel, fallback=500 * 10**decimals, decimals=decimals)
        return WalletAction(
            action_type="transfer",
            token=token,
            chain_id=chain_id,
            sender=sender,
            recipient=recipient,
            amount=amount,
            decimals=decimals,
            source="attack",
            attack_id=attack.attack_id,
        )


def _render_output(output: dict) -> str:
    return " ".join(f"{key}={value}" for key, value in output.items())
