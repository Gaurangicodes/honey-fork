"""Policy version management and stacked enforcement (FR-PL-02, FR-PL-04).

The proxy in ``policy.py`` answers "does *this* policy allow this action". This
module owns the two things the proxy deliberately does not:

* **Versioning** (FR-DB-02): policy versions are append-only. Applying a policy
  creates a new applied version rather than mutating history, and a historical
  report keeps referencing the version it ran under.
* **Stacking** (FR-PL-03/FR-PL-05): once a recipient allowlist *and* an amount
  cap are both applied, a transaction must satisfy *every* active policy. A
  single active policy would let a developer apply the amount cap and silently
  drop the allowlist they approved a minute earlier.

Templates are documented here so the UI and the compiler agree on what a
supported rule means (FR-PL-07).
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import Policy, PolicyStatus, PolicyType


@dataclass(frozen=True)
class PolicyTemplate:
    """FR-PL-07: the plain-language contract of a supported policy type."""

    policy_type: PolicyType
    label: str
    summary: str
    parameters: tuple[str, ...]
    blocks: str
    legitimate_impact: str


POLICY_TEMPLATES: dict[PolicyType, PolicyTemplate] = {
    PolicyType.RECIPIENT_ALLOWLIST: PolicyTemplate(
        policy_type=PolicyType.RECIPIENT_ALLOWLIST,
        label="Recipient allowlist",
        summary="Only explicitly approved recipients may receive transfers.",
        parameters=("allowed_recipients",),
        blocks="Any transfer whose recipient is not on the allowlist.",
        legitimate_impact=(
            "Transfers to approved recipients are unaffected. A new legitimate "
            "counterparty must be added to the allowlist first."
        ),
    ),
    PolicyType.MAX_AMOUNT: PolicyTemplate(
        policy_type=PolicyType.MAX_AMOUNT,
        label="Maximum transaction amount",
        summary="Transfers above a configured limit are rejected.",
        parameters=("max_amount", "decimals"),
        blocks="Any single transfer whose amount exceeds max_amount.",
        legitimate_impact=(
            "Transfers at or below the limit are unaffected. A larger legitimate "
            "transfer requires raising the limit explicitly."
        ),
    ),
}


def template_for(policy_type: PolicyType) -> PolicyTemplate | None:
    return POLICY_TEMPLATES.get(policy_type)


def supported_policy_types() -> list[PolicyType]:
    return list(POLICY_TEMPLATES)


class PolicyRegistry:
    """Append-only policy versions and the active stack (FR-DB-02, FR-PL-04)."""

    def __init__(self, store) -> None:
        self.store = store

    # -- versioning ----------------------------------------------------------
    def next_version(self, policy_type: PolicyType) -> str:
        """Return the next version string for a policy type.

        Version numbers are per type and monotonic, so "allowlist v2" is
        unambiguous even when amount-cap versions exist alongside it.

        Uses max+1 rather than count+1: versions are sparse once a proposal is
        superseded or a policy is rejected, and counting would then reissue a
        version number that history already uses.
        """
        existing = [
            p for p in self.store.list_policies() if p.type is policy_type
        ]
        highest = 0
        for policy in existing:
            try:
                highest = max(highest, int(policy.version))
            except (TypeError, ValueError):
                # A non-numeric version (hand-written fixture) does not
                # participate in numbering but must not break it either.
                continue
        return str(highest + 1)

    def find_proposed_equivalent(self, policy: Policy) -> Policy | None:
        """FR-DB-02: an unapplied proposal for the same rule and source run.

        Proposing the same fix twice must not mint a second version number: the
        operator is looking at the same rule, and inflating the version makes an
        applied policy read as v7 when it is the first one in force.
        """
        for existing in self.store.list_policies():
            if existing.status is not PolicyStatus.PROPOSED:
                continue
            if (
                existing.type is policy.type
                and existing.parameters == policy.parameters
                and existing.source_run_id == policy.source_run_id
                and existing.source_attack_id == policy.source_attack_id
            ):
                return existing
        return None

    def record(self, policy: Policy) -> Policy:
        """Persist a new policy version. History is never rewritten."""
        self.store.save_policy(policy)
        return policy

    def history(self, policy_type: PolicyType | None = None) -> list[Policy]:
        policies = self.store.list_policies()
        if policy_type is not None:
            policies = [p for p in policies if p.type is policy_type]
        return policies

    # -- active stack --------------------------------------------------------
    def active_policies(self) -> list[Policy]:
        """The applied policy stack, one per type, newest first.

        The store returns rows oldest-first, so the last applied policy of each
        type is the effective one for that type.
        """
        latest: dict[PolicyType, Policy] = {}
        for policy in self.store.list_applied_policies():
            latest[policy.type] = policy
        return list(latest.values())
