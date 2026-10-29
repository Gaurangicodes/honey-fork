"""Sandbox manager (FR-SB-01, FR-SB-02, FR-SB-04).

Owns the deterministic sandbox environment: test accounts, mock ERC-20 token,
initial balances, state snapshots/fingerprints, resets and balance-delta
calculation. All accounts are disposable test accounts; no production keys or
real funds are involved (SR-01, SR-07).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from ..core.models import BalanceDelta, EnvironmentSnapshot
from .chain import SandboxChain, SimulatedChain


@dataclass
class SandboxEnvironment:
    """FR-SB-01: one local EVM-compatible environment with known state."""

    environment_id: str
    chain: SandboxChain
    token_contract: str
    agent_address: str
    approved_recipient: str
    unauthorized_recipient: str
    # Balances keyed by role -> amount in smallest token units.
    initial_balances: dict[str, int] = field(default_factory=dict)
    agent_initial_balance: int = 0
    decimals: int = 18

    def role_address(self, role: str) -> str:
        return {
            "agent": self.agent_address,
            "approved_recipient": self.approved_recipient,
            "unauthorized_recipient": self.unauthorized_recipient,
        }[role]

    def addresses(self) -> dict[str, str]:
        return {
            "agent": self.agent_address,
            "approved_recipient": self.approved_recipient,
            "unauthorized_recipient": self.unauthorized_recipient,
        }


class SandboxManager:
    """Initializes, snapshots, resets and measures the sandbox."""

    def __init__(self, environment: SandboxEnvironment) -> None:
        self.environment = environment
        self._last_snapshot: EnvironmentSnapshot | None = None
        self.reset()

    # -- lifecycle -----------------------------------------------------------
    def reset(self) -> EnvironmentSnapshot:
        """FR-SB-01 / FR-UI-07: restore known initial balances.

        Balances are *set* to the configured initial values, not added on top,
        so repeated resets are idempotent. Only chain state is touched;
        historical reports live in the evidence store and are never affected.
        """
        chain = self.environment.chain
        env = self.environment
        state = {
            "chain_id": chain.chain_id,
            "token_contract": env.token_contract,
            "block_number": 1,
            "balances": {
                f"{env.role_address(role).lower()}|{env.token_contract.lower()}": amount
                for role, amount in env.initial_balances.items()
            },
        }
        chain.import_state(state)
        return self.capture_state(run_id=None, policy_version=None, attack_id=None)

    def capture_state(
        self,
        run_id: str | None,
        policy_version: str | None,
        attack_id: str | None,
    ) -> EnvironmentSnapshot:
        """FR-SB-02: capture chain id, block, addresses, balances, config hash."""
        env = self.environment
        balances = {
            role: env.chain.get_balance(addr, env.token_contract)
            for role, addr in env.addresses().items()
        }
        config = {
            "environment_id": env.environment_id,
            "chain_id": env.chain.chain_id,
            "token_contract": env.token_contract,
            "addresses": env.addresses(),
            "decimals": env.decimals,
            "initial_balances": env.initial_balances,
        }
        snapshot = EnvironmentSnapshot(
            run_id=run_id,
            chain_id=env.chain.chain_id,
            block_number=env.chain.block_number(),
            wallet_addresses=env.addresses(),
            token_contract=env.token_contract,
            balances=balances,
            configuration_hash=_hash_config(config),
            policy_version=policy_version,
            attack_id=attack_id,
        )
        self._last_snapshot = snapshot
        return snapshot

    def restore(self, snapshot: EnvironmentSnapshot) -> EnvironmentSnapshot:
        """Restore equivalent state before a replay (FR-RP-01 / FR-RP-06)."""
        state = {
            "chain_id": snapshot.chain_id,
            "token_contract": snapshot.token_contract,
            "block_number": snapshot.block_number,
            "balances": {
                f"{snapshot.wallet_addresses.get(role, role).lower()}|{snapshot.token_contract.lower()}": amount
                for role, amount in snapshot.balances.items()
            },
        }
        self.environment.chain.import_state(state)
        return self.capture_state(
            run_id=None,
            policy_version=snapshot.policy_version,
            attack_id=snapshot.attack_id,
        )

    @property
    def last_snapshot(self) -> EnvironmentSnapshot | None:
        return self._last_snapshot

    # -- measurement ---------------------------------------------------------
    def balance_deltas(self, before: EnvironmentSnapshot) -> list[BalanceDelta]:
        """FR-SB-04: deltaB = balance_after - balance_before for each address."""
        env = self.environment
        deltas: list[BalanceDelta] = []
        for role, address in env.addresses().items():
            after = env.chain.get_balance(address, env.token_contract)
            previous = before.balances.get(role, 0)
            deltas.append(
                BalanceDelta(
                    address=address,
                    token=env.token_contract,
                    before=previous,
                    after=after,
                    delta=after - previous,
                )
            )
        return deltas


def _hash_config(config: dict) -> str:
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"))
    return "0x" + hashlib.sha256(canonical.encode()).hexdigest()


def default_demo_environment(
    environment_id: str = "local-evm-demo",
    chain: SandboxChain | None = None,
    agent_balance: int = 10_000 * 10**18,
) -> SandboxEnvironment:
    """Build the standard demo environment used by agents and tests."""
    from ..core.constants import (
        AGENT_ADDRESS,
        APPROVED_RECIPIENT,
        TOKEN_CONTRACT,
        TOKEN_DECIMALS,
        UNAUTHORIZED_RECIPIENT,
    )

    chain = chain or SimulatedChain(chain_id=31337)
    env = SandboxEnvironment(
        environment_id=environment_id,
        chain=chain,
        token_contract=TOKEN_CONTRACT,
        agent_address=AGENT_ADDRESS,
        approved_recipient=APPROVED_RECIPIENT,
        unauthorized_recipient=UNAUTHORIZED_RECIPIENT,
        initial_balances={
            "agent": agent_balance,
            "approved_recipient": 0,
            "unauthorized_recipient": 0,
        },
        agent_initial_balance=agent_balance,
        decimals=TOKEN_DECIMALS,
    )
    # Bring the chain to its documented initial state immediately, so a bare
    # environment (without a manager) is already in the known starting state.
    SandboxManager(env)
    return env
