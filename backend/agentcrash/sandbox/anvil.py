"""Real local EVM adapter (Anvil / any EVM JSON-RPC node).

This is an optional adapter. The MVP demo runs on `SimulatedChain`; this class
exists so a team with Anvil running can switch the environment to a real chain
without touching the verifier or policy proxy (architecture layer 20.4).

It deliberately implements only what Module 2 needs: chain identity, block
number, native-balance reads and receipt lookup. Token transfers are submitted
as pre-signed raw transactions supplied by the caller's test wallet; no
production keys ever reach this code (SR-01, SR-06).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ..core.errors import SandboxUnavailable
from .chain import TransferFailed, TransferReceipt


class AnvilChain:
    def __init__(
        self,
        rpc_url: str = "http://127.0.0.1:8545",
        chain_id: int = 31337,
        token_contract: str | None = None,
        expected_chain_id: int | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.rpc_url = rpc_url
        self.chain_id = chain_id
        self.token_contract = token_contract or "0xToken0000000000000000000000000000000001"
        self.expected_chain_id = expected_chain_id if expected_chain_id is not None else chain_id
        self._timeout = timeout
        self._client = httpx.Client(timeout=timeout)
        self._receipts: dict[str, TransferReceipt] = {}
        self._assert_chain_identity()

    # -- JSON-RPC plumbing ---------------------------------------------------
    def _rpc(self, method: str, params: list[Any]) -> Any:
        try:
            response = self._client.post(
                self.rpc_url,
                json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params},
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:  # pragma: no cover - network failure path
            raise SandboxUnavailable(f"RPC call {method} failed: {exc}") from exc
        payload = response.json()
        if "error" in payload:
            raise SandboxUnavailable(f"RPC error for {method}: {payload['error']}")
        return payload.get("result")

    def _assert_chain_identity(self) -> None:
        """SR-06: verify we are pointed at the intended local chain."""
        try:
            live_chain_id = int(self._rpc("eth_chainId", []), 16)
        except (TypeError, ValueError) as exc:  # pragma: no cover
            raise SandboxUnavailable("could not read chain id from RPC") from exc
        if live_chain_id != self.expected_chain_id:
            raise SandboxUnavailable(
                f"connected chain id {live_chain_id} != expected {self.expected_chain_id}"
            )
        self.chain_id = live_chain_id

    # -- state ---------------------------------------------------------------
    def block_number(self) -> int:
        return int(self._rpc("eth_blockNumber", []), 16)

    def get_balance(self, address: str, token: str) -> int:
        # Native balance only; ERC-20 balance reads require a token ABI and are
        # out of scope for the MVP simulator parity. Callers that need token
        # balances should use the simulated chain or extend this adapter.
        return int(self._rpc("eth_getBalance", [address, "latest"]), 16)

    def transfer(
        self, sender: str, recipient: str, token: str, amount: int, decimals: int = 18
    ) -> TransferReceipt:
        raise NotImplementedError(
            "Raw signed-transaction submission is handled by the wallet tool in "
            "Module 1; Module 2 verifies the resulting receipt via get_receipt()."
        )

    def get_receipt(self, tx_hash: str) -> TransferReceipt | None:
        raw = self._rpc("eth_getTransactionReceipt", [tx_hash])
        if not raw:
            return None
        status = "success" if int(raw.get("status", "0x0"), 16) == 1 else "reverted"
        receipt = TransferReceipt(
            tx_hash=tx_hash,
            status=status,
            block_number=int(raw.get("blockNumber", "0x0"), 16),
            sender=raw.get("from", ""),
            recipient=raw.get("to", "") or "",
            token=self.token_contract,
            amount=0,
            gas_used=int(raw.get("gasUsed", "0x0"), 16),
        )
        self._receipts[tx_hash] = receipt
        return receipt

    def export_state(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "token_contract": self.token_contract,
            "block_number": self.block_number(),
            "balances": {},
            "adapter": "anvil",
        }

    def import_state(self, state: dict[str, Any]) -> None:  # pragma: no cover
        raise NotImplementedError(
            "Restoring Anvil state requires anvil_snapshot/anvil_revert; use the "
            "simulated chain for deterministic replays in the MVP."
        )


def receipt_to_json(receipt: TransferReceipt) -> str:
    return json.dumps(receipt.to_dict(), sort_keys=True)


__all__ = ["AnvilChain", "TransferFailed", "receipt_to_json"]
