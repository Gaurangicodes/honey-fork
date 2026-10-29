"""Sandbox agent runtime and registry (Module 1).

Two configurations with a documented difference (FR-AG-02):

* ``agent-vulnerable-01`` - ``guardrail="none"``: the wallet tool submits
  directly to the sandbox, with no policy enforcement path.
* ``agent-guarded-01`` - ``guardrail="policy_proxy"``: same model and same tool
  set, but its wallet tool only reaches the sandbox through the policy proxy.
  This is what makes the two configurations comparable: identical agent
  behavior, different enforcement.

Both configurations are driven by the same deterministic rule model, which
stands in for an LLM tool-calling loop behind the same interface. Because the
model is identical, an attack that manipulates one manipulates the other; only
the enforcement boundary differs. That is exactly the property the product
needs to demonstrate.
"""

from __future__ import annotations

import re

from .models import AgentConfiguration, AttackDefinition, WalletAction

DEFAULT_AGENTS: list[AgentConfiguration] = [
    AgentConfiguration(
        agent_id="agent-vulnerable-01",
        name="Vulnerable Sandbox Agent",
        model_id="sandbox-rule-agent",
        configuration_version="1.0.0",
        tool_set=["wallet.transfer", "token.read_metadata", "oracle.get_price"],
        environment_id="local-evm-demo",
        guardrail="none",
        description="No guardrails: follows instructions embedded in untrusted content.",
    ),
    AgentConfiguration(
        agent_id="agent-guarded-01",
        name="Guarded Sandbox Agent",
        model_id="sandbox-rule-agent",
        configuration_version="1.0.0",
        tool_set=["wallet.transfer", "token.read_metadata", "oracle.get_price"],
        environment_id="local-evm-demo",
        guardrail="policy_proxy",
        description="Same model and tools, but the wallet tool only reaches the sandbox through the policy proxy.",
    ),
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


def agent_registry() -> list[AgentConfiguration]:
    return [a.model_copy(deep=True) for a in DEFAULT_AGENTS]


def get_agent(agent_id: str) -> AgentConfiguration | None:
    for agent in DEFAULT_AGENTS:
        if agent.agent_id == agent_id:
            return agent.model_copy(deep=True)
    return None


class SandboxAgent:
    def __init__(self, config: AgentConfiguration) -> None:
        self.config = config

    def propose_action(
        self,
        attack: AttackDefinition,
        *,
        sender: str,
        token: str,
        chain_id: int,
        unauthorized_recipient: str,
        decimals: int = 18,
    ) -> WalletAction | None:
        """Return the structured action the agent wants to take.

        A `None` return means the agent produced no wallet action (the attack
        did not trigger). The action is a *proposal*; enforcement happens in the
        policy proxy, not here.
        """
        recipient_match = _ADDRESS_RE.search(attack.input_payload)
        if not recipient_match:
            return None
        recipient = recipient_match.group(0)

        # Both configurations share the same rule model, so both are persuaded
        # by the untrusted content and propose the same transfer. What differs
        # is the enforcement boundary the action must pass through, not the
        # agent's willingness to act.
        amount = _extract_amount(
            attack.input_payload, fallback=500 * 10**decimals, decimals=decimals
        )
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
