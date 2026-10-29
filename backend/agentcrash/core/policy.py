"""Transaction Policy Proxy and Policy Compiler (Module 3).

The proxy is the mandatory enforcement point for every registered wallet
transaction path (FR-PL-03). It evaluates structured `WalletAction` arguments,
never free-form model text, and returns an explicit allow/deny decision with a
machine-readable reason. A denial happens before signing or submission.
"""

from __future__ import annotations

from typing import Any

from .models import (
    AttackDefinition,
    Policy,
    PolicyDecision,
    PolicyStatus,
    PolicyType,
    WalletAction,
)


def normalize_address(address: str) -> str:
    """FR-PL-02: validate and normalize addresses for comparison.

    EVM addresses are hex strings of 40 hex digits, optionally 0x-prefixed.
    Comparison is case-insensitive (EIP-55 checksum is not enforced in the MVP).
    """
    if not isinstance(address, str):
        raise ValueError("address must be a string")
    candidate = address.strip()
    if candidate.startswith(("0x", "0X")):
        candidate = candidate[2:]
    if len(candidate) != 40:
        raise ValueError(f"address must be 40 hex characters, got {len(candidate)}")
    int(candidate, 16)  # raises ValueError on non-hex input
    return "0x" + candidate.lower()


def format_amount(amount: int, decimals: int) -> str:
    """Render smallest-unit amounts with correct token decimals (FR-PL-02)."""
    if decimals < 0:
        raise ValueError("decimals must be non-negative")
    if decimals == 0:
        return str(amount)
    scale = 10**decimals
    whole, fraction = divmod(amount, scale)
    return f"{whole}.{fraction:0{decimals}d}".rstrip("0").rstrip(".")


def _diff_line(name: str, before: Any, after: Any, note: str = "") -> dict[str, Any]:
    """FR-PL-07: one structured before/after entry for the policy diff."""
    return {"parameter": name, "before": before, "after": after, "note": note}


class PolicyProxy:
    """Enforces the currently active policy version on structured actions."""

    def __init__(
        self,
        active_policy: Policy | None = None,
        expected_chain_id: int | None = None,
        active_policies: list[Policy] | None = None,
    ) -> None:
        # `active_policies` is the applied stack (FR-PL-03). `active_policy` is
        # kept as the single-policy convenience for callers that only ever apply
        # one rule; when both are given the stack wins.
        self.active_policies: list[Policy] = list(active_policies or [])
        if active_policy is not None and not self.active_policies:
            self.active_policies = [active_policy]
        # FR-SB-01/FR-PL-03: the chain identity the proxy is allowed to submit to.
        # Defaults to the Anvil/local demo chain id.
        self.expected_chain_id = 31337 if expected_chain_id is None else expected_chain_id

    def set_stack(self, policies: list[Policy]) -> None:
        self.active_policies = list(policies)

    def add_to_stack(self, policy: Policy) -> None:
        """Replace any active policy of the same type, then add this one.

        One effective policy per type keeps the stack predictable: applying a
        second allowlist supersedes the first rather than creating an
        unsatisfiable pair.
        """
        self.active_policies = [p for p in self.active_policies if p.type is not policy.type]
        self.active_policies.append(policy)

    def set_active_policy(self, policy: Policy | None) -> None:
        self.active_policies = [policy] if policy is not None else []

    @property
    def active_policy(self) -> Policy | None:
        return self.active_policies[-1] if self.active_policies else None

    @property
    def active_policy_version(self) -> str | None:
        return self.active_policy.version if self.active_policy else None

    @property
    def active_policy_versions(self) -> list[str]:
        return [p.version for p in self.active_policies]

    def evaluate(self, action: WalletAction) -> PolicyDecision:
        """FR-PL-03: the action must satisfy every active policy."""
        if not self.active_policies:
            return self.evaluate_with(None, action)
        for policy in self.active_policies:
            decision = self.evaluate_with(policy, action)
            if not decision.allowed:
                return decision
        versions = ", ".join(f"v{p.version} ({p.type.value})" for p in self.active_policies)
        return PolicyDecision(
            allowed=True,
            reason_code="ALL_POLICIES_ALLOWED",
            reason=f"Action satisfies all active policies: {versions}",
            policy_version=",".join(self.active_policy_versions),
            checked_action=action,
        )

    def evaluate_with(
        self, policy: Policy | None, action: WalletAction
    ) -> PolicyDecision:
        """Evaluate an action against an explicit policy, without changing which
        policy is active. Used for pre-application dry runs."""
        # Chain identity is checked before any rule: a correctly-formed transfer
        # aimed at the wrong chain must never be submitted (FR-SB-01, SR-06).
        if action.chain_id != self.expected_chain_id:
            return PolicyDecision(
                allowed=False,
                reason_code="CHAIN_MISMATCH",
                reason=(
                    f"Action targets chain {action.chain_id} but the sandbox chain is "
                    f"{self.expected_chain_id}"
                ),
                policy_version=policy.version if policy else None,
                checked_action=action,
            )
        if policy is None:
            return PolicyDecision(
                allowed=True,
                reason_code="NO_POLICY",
                reason="No policy active; sandbox-only transaction permitted",
                policy_version=None,
                checked_action=action,
            )
        if policy.type is PolicyType.RECIPIENT_ALLOWLIST:
            return self._evaluate_allowlist(policy, action)
        if policy.type is PolicyType.MAX_AMOUNT:
            return self._evaluate_max_amount(policy, action)
        return PolicyDecision(
            allowed=False,
            reason_code="UNSUPPORTED_POLICY_TYPE",
            reason=f"Policy type {policy.type} is not enforceable",
            policy_version=policy.version,
            checked_action=action,
        )

    def _evaluate_allowlist(self, policy: Policy, action: WalletAction) -> PolicyDecision:
        allowed_raw = policy.parameters.get("allowed_recipients", [])
        try:
            allowed = {normalize_address(a) for a in allowed_raw}
            recipient = normalize_address(action.recipient)
        except ValueError as exc:
            return PolicyDecision(
                allowed=False,
                reason_code="POLICY_VALIDATION_FAILED",
                reason=f"Invalid address in policy or action: {exc}",
                policy_version=policy.version,
                checked_action=action,
            )
        if recipient in allowed:
            return PolicyDecision(
                allowed=True,
                reason_code="RECIPIENT_ALLOWED",
                reason=f"Recipient {recipient} is on the allowlist",
                policy_version=policy.version,
                checked_action=action,
            )
        return PolicyDecision(
            allowed=False,
            reason_code="RECIPIENT_NOT_ALLOWED",
            reason=f"Recipient {recipient} is not on the allowlist",
            policy_version=policy.version,
            checked_action=action,
        )

    def _evaluate_max_amount(self, policy: Policy, action: WalletAction) -> PolicyDecision:
        try:
            limit = int(policy.parameters["max_amount"])
            expected_decimals = int(policy.parameters.get("decimals", action.decimals))
        except (KeyError, TypeError, ValueError) as exc:
            return PolicyDecision(
                allowed=False,
                reason_code="POLICY_VALIDATION_FAILED",
                reason=f"Invalid max-amount policy parameters: {exc}",
                policy_version=policy.version,
                checked_action=action,
            )
        if action.decimals != expected_decimals:
            return PolicyDecision(
                allowed=False,
                reason_code="DECIMALS_MISMATCH",
                reason=(
                    f"Action uses {action.decimals} decimals but policy expects "
                    f"{expected_decimals}"
                ),
                policy_version=policy.version,
                checked_action=action,
            )
        if action.amount <= limit:
            return PolicyDecision(
                allowed=True,
                reason_code="WITHIN_LIMIT",
                reason=(
                    f"Amount {format_amount(action.amount, action.decimals)} is within the "
                    f"limit {format_amount(limit, action.decimals)}"
                ),
                policy_version=policy.version,
                checked_action=action,
            )
        return PolicyDecision(
            allowed=False,
            reason_code="AMOUNT_EXCEEDS_LIMIT",
            reason=(
                f"Amount {format_amount(action.amount, action.decimals)} exceeds the limit "
                f"{format_amount(limit, action.decimals)}"
            ),
            policy_version=policy.version,
            checked_action=action,
        )


class PolicyCompiler:
    """Deterministic rule-based mapping from a verified attack to a policy.

    Unsupported attacks are reported as unsupported rather than being given a
    generic rule (FR-PL-06, FR-PL-07).
    """

    def compile(
        self,
        *,
        attack: AttackDefinition,
        run_id: str,
        observed: dict[str, Any],
        existing_versions: int = 0,
    ) -> Policy | None:
        if attack.supported_policy_type is None:
            return None
        version = str(existing_versions + 1)
        if attack.supported_policy_type is PolicyType.RECIPIENT_ALLOWLIST:
            approved = observed.get("approved_recipient")
            if not approved:
                return None
            normalized = normalize_address(approved)
            policy = Policy(
                version=version,
                type=PolicyType.RECIPIENT_ALLOWLIST,
                parameters={"allowed_recipients": [normalized]},
                source_run_id=run_id,
                source_attack_id=attack.attack_id,
                rationale=(
                    f"Attack {attack.attack_id} moved funds to an unauthorized recipient "
                    f"{observed.get('unauthorized_recipient')}. Restricting transfers to "
                    f"approved recipients prevents the observed violation."
                ),
                expected_effect="Transfers to recipients outside the allowlist are rejected before submission.",
                legitimate_task_impact=(
                    "Legitimate transfers to approved recipients continue to work; transfers "
                    "to any other address are blocked and must be added to the allowlist."
                ),
                status=PolicyStatus.PROPOSED,
            )
            policy.diff = [
                _diff_line(
                    "allowed_recipients",
                    before=[],
                    after=[normalized],
                    note="recipients permitted to receive transfers",
                )
            ]
            return policy
        if attack.supported_policy_type is PolicyType.MAX_AMOUNT:
            limit = observed.get("suggested_limit")
            decimals = observed.get("decimals", 18)
            if limit is None:
                return None
            policy = Policy(
                version=version,
                type=PolicyType.MAX_AMOUNT,
                parameters={"max_amount": int(limit), "decimals": int(decimals)},
                source_run_id=run_id,
                source_attack_id=attack.attack_id,
                rationale=(
                    f"Attack {attack.attack_id} transferred more than the configured safe "
                    f"limit. Capping the maximum transfer amount limits single-transaction loss."
                ),
                expected_effect="Transfers above the configured limit are rejected before submission.",
                legitimate_task_impact=(
                    "Legitimate transfers at or below the limit continue to work; larger "
                    "transfers require raising the limit explicitly."
                ),
                status=PolicyStatus.PROPOSED,
            )
            policy.diff = [
                _diff_line(
                    "max_amount",
                    before="unlimited",
                    after=f"{format_amount(int(limit), int(decimals))} TST",
                    note="largest single transfer permitted",
                )
            ]
            return policy
        return None
