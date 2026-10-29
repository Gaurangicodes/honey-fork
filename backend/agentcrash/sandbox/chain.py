"""Sandbox transaction adapter (architecture layer 20.4).

`SandboxChain` is the only path to chain state. Two implementations are
provided:

* `SimulatedChain` - deterministic, in-process EVM-like simulator. Default for
  the MVP, needs no external node and gives byte-exact balance arithmetic.
* `AnvilChain` (see ``anvil.py``) - real local Anvil/EVM node over JSON-RPC.

Both expose the same interface so the verifier and policy proxy never depend on
which one is running. Every transfer is a *test* transfer between disposable
accounts; production keys are never used (SR-01).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Protocol

from ..core.errors import SandboxUnavailable


class TransferFailed(Exception):
    """Raised by the adapter when a submitted transaction reverts/fails."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class TransferReceipt:
    """FR-SB-05: transaction evidence captured from the sandbox."""

    tx_hash: str
    status: str  # "success" | "reverted"
    block_number: int
    sender: str
    recipient: str
    token: str
    amount: int
    gas_used: int = 21000
    logs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "transaction_hash": self.tx_hash,
            "status": self.status,
            "block_number": self.block_number,
            "sender": self.sender,
            "recipient": self.recipient,
            "token": self.token,
            "amount": self.amount,
            "gas_used": self.gas_used,
            "logs": self.logs,
        }


class SandboxChain(Protocol):
    chain_id: int

    def block_number(self) -> int: ...

    def get_balance(self, address: str, token: str) -> int: ...

    def transfer(
        self, sender: str, recipient: str, token: str, amount: int, decimals: int = 18
    ) -> TransferReceipt: ...

    def get_receipt(self, tx_hash: str) -> TransferReceipt | None: ...

    def export_state(self) -> dict[str, Any]: ...

    def import_state(self, state: dict[str, Any]) -> None: ...


class SimulatedChain:
    """Deterministic in-process token ledger.

    State is a plain dict of ``balances[(address, token)] = int``. A transfer
    debits the sender and credits the recipient atomically; an insufficient
    balance makes the transaction revert rather than partially apply, which
    mirrors ERC-20 semantics closely enough for outcome verification.
    """

    def __init__(self, chain_id: int = 31337, token_contract: str | None = None) -> None:
        self.chain_id = chain_id
        self.token_contract = token_contract or "0xToken0000000000000000000000000000000001"
        self._balances: dict[tuple[str, str], int] = {}
        self._block = 1
        self._receipts: dict[str, TransferReceipt] = {}
        self._tx_counter = 0

    # -- state ---------------------------------------------------------------
    def mint(self, address: str, token: str, amount: int) -> None:
        if amount < 0:
            raise ValueError("cannot mint a negative amount")
        key = (address.lower(), token.lower())
        self._balances[key] = self._balances.get(key, 0) + amount

    def get_balance(self, address: str, token: str) -> int:
        return self._balances.get((address.lower(), token.lower()), 0)

    def block_number(self) -> int:
        return self._block

    # -- transactions --------------------------------------------------------
    def transfer(
        self, sender: str, recipient: str, token: str, amount: int, decimals: int = 18
    ) -> TransferReceipt:
        if amount <= 0:
            raise TransferFailed("transfer amount must be positive")
        sender_key = (sender.lower(), token.lower())
        recipient_key = (recipient.lower(), token.lower())
        sender_balance = self._balances.get(sender_key, 0)
        self._tx_counter += 1
        tx_hash = "0x" + hashlib.sha256(
            f"{self.chain_id}:{self._block}:{self._tx_counter}:{sender}:{recipient}:{amount}".encode()
        ).hexdigest()[:64]
        self._block += 1

        if sender_balance < amount:
            receipt = TransferReceipt(
                tx_hash=tx_hash,
                status="reverted",
                block_number=self._block,
                sender=sender,
                recipient=recipient,
                token=token,
                amount=amount,
                gas_used=21000,
            )
            self._receipts[tx_hash] = receipt
            raise TransferFailed("insufficient token balance")

        self._balances[sender_key] = sender_balance - amount
        self._balances[recipient_key] = self._balances.get(recipient_key, 0) + amount
        receipt = TransferReceipt(
            tx_hash=tx_hash,
            status="success",
            block_number=self._block,
            sender=sender,
            recipient=recipient,
            token=token,
            amount=amount,
            logs=[
                {
                    "event": "Transfer",
                    "from": sender,
                    "to": recipient,
                    "value": str(amount),
                    "token": token,
                }
            ],
        )
        self._receipts[tx_hash] = receipt
        return receipt

    def get_receipt(self, tx_hash: str) -> TransferReceipt | None:
        return self._receipts.get(tx_hash)

    # -- snapshot / restore --------------------------------------------------
    def export_state(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "token_contract": self.token_contract,
            "block_number": self._block,
            "balances": {
                f"{addr}|{token}": amount
                for (addr, token), amount in self._balances.items()
            },
        }

    def import_state(self, state: dict[str, Any]) -> None:
        if state.get("chain_id") != self.chain_id:
            raise SandboxUnavailable("snapshot chain id does not match this sandbox")
        self._balances = {}
        for key, amount in state.get("balances", {}).items():
            addr, token = key.split("|", 1)
            self._balances[(addr, token)] = int(amount)
        self._block = int(state.get("block_number", 1))
        self._receipts = {}
