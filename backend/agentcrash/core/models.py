"""Core domain model shared by every AgentCrash Replay module.

Field names follow the SRS section 6 data model. All monetary values are stored
as integers in the token's smallest unit (like wei / token decimals) so that
balance comparisons are exact and never depend on floating point.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


class Verdict(str, Enum):
    """FR-SB-03 / FR-RP-04 verdict vocabulary.

    Only these four values may describe a trial outcome. Infrastructure
    failures are recorded separately as TEST_ERROR and are excluded from rate
    denominators (FR-RE-01).
    """

    EXPLOIT_SUCCEEDED = "EXPLOIT_SUCCEEDED"
    ATTEMPT_BLOCKED = "ATTEMPT_BLOCKED"
    ATTACK_NOT_TRIGGERED = "ATTACK_NOT_TRIGGERED"
    TEST_ERROR = "TEST_ERROR"


class RunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunType(str, Enum):
    ATTACK = "attack"
    REPLAY = "replay"
    REGRESSION = "regression"


class PolicyType(str, Enum):
    RECIPIENT_ALLOWLIST = "recipient_allowlist"
    MAX_AMOUNT = "max_transaction_amount"


class PolicyStatus(str, Enum):
    PROPOSED = "proposed"
    APPLIED = "applied"
    REJECTED = "rejected"


class FixStatus(str, Enum):
    """FR-RP-04 fix status for a replay."""

    VERIFIED = "VERIFIED"
    BLOCKED_BUT_REGRESSION = "BLOCKED_BUT_REGRESSION"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    TEST_ERROR = "TEST_ERROR"
    INCOMPLETE = "INCOMPLETE"


class VerificationStatus(str, Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class ErrorCode(str, Enum):
    """Stable API error codes (SRS section 7.4)."""

    AGENT_NOT_FOUND = "AGENT_NOT_FOUND"
    ATTACK_NOT_FOUND = "ATTACK_NOT_FOUND"
    SANDBOX_UNAVAILABLE = "SANDBOX_UNAVAILABLE"
    POLICY_VALIDATION_FAILED = "POLICY_VALIDATION_FAILED"
    REPLAY_STATE_MISMATCH = "REPLAY_STATE_MISMATCH"
    MODEL_PROVIDER_ERROR = "MODEL_PROVIDER_ERROR"
    RUN_NOT_FOUND = "RUN_NOT_FOUND"
    POLICY_NOT_FOUND = "POLICY_NOT_FOUND"
    REPORT_NOT_FOUND = "REPORT_NOT_FOUND"
    INVALID_REQUEST = "INVALID_REQUEST"


class AgentConfiguration(BaseModel):
    """FR-AG-01: a registered sandbox agent configuration."""

    agent_id: str
    name: str
    model_id: str
    configuration_version: str = "1.0.0"
    tool_set: list[str] = Field(default_factory=list)
    policy_version: str | None = None
    environment_id: str
    # Documented differentiator between the two MVP configurations (FR-AG-02).
    guardrail: Literal["none", "system_prompt_only", "policy_proxy"] = "none"
    description: str = ""
    initial_balance: int = 0


class AttackDefinition(BaseModel):
    """FR-AT-01: versioned attack library entry."""

    attack_id: str
    version: str = "1.0.0"
    name: str
    category: str
    description: str = ""
    input_payload: str
    target_capability: str = "wallet.transfer"
    expected_legitimate_behavior: str = ""
    expected_unsafe_behavior: str = ""
    success_condition: str
    source_reference: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "high"
    supported_policy_type: PolicyType | None = None
    test_status: Literal["validated", "unvalidated"] = "validated"
    environment_setup: dict[str, Any] = Field(default_factory=dict)


class WalletAction(BaseModel):
    """Structured transaction request produced by a wallet tool.

    The policy proxy evaluates these fields, never free-form model text
    (FR-PL-03).
    """

    action_type: Literal["transfer", "approve"] = "transfer"
    token: str
    chain_id: int
    sender: str
    recipient: str
    amount: int
    decimals: int = 18
    source: str = "agent"  # attack | agent | regression
    attack_id: str | None = None


class BalanceDelta(BaseModel):
    """FR-SB-04: deltaB = balance_after - balance_before."""

    address: str
    token: str
    before: int
    after: int
    delta: int


class EnvironmentSnapshot(BaseModel):
    """FR-SB-02: initial-state fingerprint used by the replay equivalence gate."""

    snapshot_id: str = Field(default_factory=lambda: new_id("snap"))
    run_id: str | None = None
    chain_id: int
    block_number: int
    wallet_addresses: dict[str, str] = Field(default_factory=dict)
    token_contract: str
    balances: dict[str, int] = Field(default_factory=dict)
    configuration_hash: str = ""
    policy_version: str | None = None
    attack_id: str | None = None
    created_at: datetime = Field(default_factory=utcnow)

    def fingerprint(self) -> str:
        """Canonical fingerprint over the state that must match on replay.

        Computed from the snapshot's own fields rather than stored separately,
        so a mutated snapshot cannot keep a stale fingerprint. The block number
        alone is insufficient (FR-SB-02), so identity, balances and token are
        all folded in.

        The active policy version is deliberately excluded: the replay runs the
        same state under a *different* policy, so requiring the policy version to
        match would make every legitimate replay fail the equivalence gate.
        """
        from .hashing import canonical_hash

        return canonical_hash(
            {
                "chain_id": self.chain_id,
                "token_contract": self.token_contract.lower(),
                "wallet_addresses": {
                    role: address.lower() for role, address in self.wallet_addresses.items()
                },
                "balances": {
                    role: int(amount) for role, amount in sorted(self.balances.items())
                },
                "configuration_hash": self.configuration_hash,
            }
        )


class EvidenceRecord(BaseModel):
    """FR-SB-05 / section 6: a single piece of run-linked evidence."""

    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    run_id: str
    event_type: str
    timestamp: datetime = Field(default_factory=utcnow)
    transaction_hash: str | None = None
    status: str | None = None
    block_number: int | None = None
    before_state: dict[str, Any] | None = None
    after_state: dict[str, Any] | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    integrity_hash: str | None = None


class Policy(BaseModel):
    """FR-PL-01/02: an enforceable, versioned wallet policy."""

    policy_id: str = Field(default_factory=lambda: new_id("policy"))
    version: str = "1"
    type: PolicyType
    parameters: dict[str, Any]
    source_run_id: str | None = None
    source_attack_id: str | None = None
    rationale: str = ""
    expected_effect: str = ""
    legitimate_task_impact: str = ""
    status: PolicyStatus = PolicyStatus.PROPOSED
    created_at: datetime = Field(default_factory=utcnow)

    @field_validator("parameters")
    @classmethod
    def _parameters_not_empty(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not value:
            raise ValueError("policy parameters must not be empty")
        return value


class PolicyDecision(BaseModel):
    """FR-PL-03: explicit allow/deny with a machine-readable reason."""

    allowed: bool
    reason_code: str
    reason: str
    policy_version: str | None = None
    checked_action: WalletAction | None = None


class RegressionResult(BaseModel):
    """Section 6: legitimate-task regression outcome."""

    regression_id: str = Field(default_factory=lambda: new_id("reg"))
    original_run_id: str
    replay_run_id: str | None = None
    policy_version: str | None = None
    attack_blocked: bool = False
    legitimate_task_passed: bool = False
    verification_status: VerificationStatus = VerificationStatus.PENDING
    fix_status: FixStatus = FixStatus.INCOMPLETE
    details: dict[str, Any] = Field(default_factory=dict)


class RunEvent(BaseModel):
    """FR-UI-03 / FR-UX-09: a timestamped, structured run event."""

    event_id: str = Field(default_factory=lambda: new_id("event"))
    run_id: str
    seq: int
    timestamp: datetime = Field(default_factory=utcnow)
    event_type: str
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class ScanRun(BaseModel):
    """Section 6: a single attack/replay/regression trial execution."""

    run_id: str = Field(default_factory=lambda: new_id("run"))
    agent_id: str
    attack_id: str
    parent_run_id: str | None = None
    run_type: RunType = RunType.ATTACK
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    status: RunStatus = RunStatus.QUEUED
    verdict: Verdict | None = None
    policy_version: str | None = None
    trial_index: int = 1
    repeat_count: int = 1
    attack_version: str = "1.0.0"
    agent_config_version: str = "1.0.0"
    environment_id: str = ""
    environment_snapshot_id: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    transaction_hashes: list[str] = Field(default_factory=list)
    balance_deltas: list[BalanceDelta] = Field(default_factory=list)
    verdict_reason: str = ""


class ScanRequest(BaseModel):
    agent_id: str
    attack_ids: list[str]
    repeat_count: int = 1
    environment_id: str = "local-evm-demo"


class Report(BaseModel):
    report_id: str = Field(default_factory=lambda: new_id("report"))
    run_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    metrics: dict[str, Any] = Field(default_factory=dict)
    sections: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    integrity_hash: str | None = None
