"""Replay receipts and the exportable report (FR-RP-03, FR-RE-06).

A receipt is the structured, JSON-exportable record of one replay: the attack
definition version, the environment, the initial-state fingerprints that prove
the replay started from equivalent state, the tool-call transcript, transaction
evidence, the policy version and the verified outcome.

Receipts are built from persisted run records only. Nothing is inferred from
model narration, and secrets never enter a receipt (FR-RP-03, SR-05) — the
export path additionally runs the redactor.
"""

from __future__ import annotations

from typing import Any

from .models import EnvironmentSnapshot, RegressionResult, ScanRun
from .reporting import compute_metrics, is_protected, is_valid, per_attack_breakdown

RECEIPT_SCHEMA_VERSION = "1.0.0"


def build_receipt(
    *,
    original: ScanRun,
    replay: ScanRun,
    regression: RegressionResult,
    baseline: EnvironmentSnapshot | None,
    restored: EnvironmentSnapshot | None,
    attack: Any,
    agent_config: Any,
    active_policies: list[Any],
) -> dict[str, Any]:
    """FR-RP-03: assemble a replay receipt from persisted records.

    `baseline` and `restored` are the fingerprints of the original run's initial
    state and the replay's initial state. Their equality is what makes the
    before/after comparison meaningful (FR-RP-06); the receipt records both so a
    reader can check the equivalence claim rather than trust it.
    """
    fingerprints_match = (
        baseline is not None
        and restored is not None
        and baseline.fingerprint() == restored.fingerprint()
    )
    return {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "kind": "replay_receipt",
        "test_configuration": {
            "agent_id": replay.agent_id,
            "agent_configuration_version": replay.agent_config_version,
            "guardrail": getattr(agent_config, "guardrail", None),
            "tool_set": list(getattr(agent_config, "tool_set", []) or []),
            "environment_id": replay.environment_id,
        },
        "attack": {
            "attack_id": attack.attack_id,
            "attack_version": attack.version,
            "name": attack.name,
            "category": attack.category,
            "severity": attack.severity,
            "source_reference": attack.source_reference,
        },
        "environment": {
            "chain_id": restored.chain_id if restored else None,
            "token_contract": restored.token_contract if restored else None,
            "block_number_at_replay_start": restored.block_number if restored else None,
        },
        # FR-RP-06: the equivalence gate, stated explicitly.
        "state_equivalence": {
            "baseline_fingerprint": baseline.fingerprint() if baseline else None,
            "replay_fingerprint": restored.fingerprint() if restored else None,
            "equivalent": fingerprints_match,
            "baseline_snapshot_id": baseline.snapshot_id if baseline else None,
            "replay_snapshot_id": restored.snapshot_id if restored else None,
        },
        "policy": {
            "applied_versions": [p.version for p in active_policies],
            "policies": [
                {
                    "policy_id": p.policy_id,
                    "type": p.type.value,
                    "version": p.version,
                    "parameters": p.parameters,
                    "status": p.status.value,
                }
                for p in active_policies
            ],
        },
        "runs": {
            "original_run_id": original.run_id,
            "replay_run_id": replay.run_id,
            "original_verdict": original.verdict.value if original.verdict else None,
            "replay_verdict": replay.verdict.value if replay.verdict else None,
            "replay_verdict_reason": replay.verdict_reason,
        },
        "tool_call_transcript": list(replay.tool_calls),
        "transaction_evidence": {
            "transaction_hashes": list(replay.transaction_hashes),
            "submitted": bool(replay.transaction_hashes),
            "note": (
                "No transaction was submitted for this replay."
                if not replay.transaction_hashes
                else "Transaction submitted to the sandbox chain; see hashes."
            ),
        },
        "balance_deltas": [d.model_dump(mode="json") for d in replay.balance_deltas],
        "outcome": {
            "attack_blocked": regression.attack_blocked,
            "legitimate_task_passed": regression.legitimate_task_passed,
            "fix_status": regression.fix_status.value,
            "verification_status": regression.verification_status.value,
            "legitimate_regression": regression.details,
        },
        "limitations": [
            "One replay is a repeated experiment, not a deterministic proof.",
            "Verified applies to this attack, agent configuration and policy version only.",
            "Model output may be nondeterministic across trials.",
        ],
    }


def build_report_payload(
    *,
    trials: list[ScanRun],
    regressions: list[RegressionResult],
    environment: Any,
    policies: list[Any],
    suites: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """FR-RE-06: the human-readable report body.

    Metrics come from `reporting.compute_metrics`, which is also what the tests
    exercise, so the numbers in the report and the numbers under test cannot
    drift apart.
    """
    metrics = compute_metrics(trials, regressions, environment=environment)
    return {
        "metrics": metrics.to_dict(),
        "per_attack": per_attack_breakdown(trials, regressions),
        "agent_and_environment": {
            "environment_id": environment.environment_id,
            "chain_id": environment.chain.chain_id,
            "token_contract": environment.token_contract,
            "decimals": environment.decimals,
        },
        "coverage": {
            "attacks_in_suite": sorted({t.attack_id for t in trials}),
            "attack_versions": sorted(
                {f"{t.attack_id}@{t.attack_version}" for t in trials}
            ),
            "trials_total": len(trials),
            "trials_valid": len([t for t in trials if is_valid(t)]),
            # Baselines and protected replays are different evidence; a reader
            # needs to see the split behind every rate (NFR-11).
            "baseline_trials": len(
                [t for t in trials if is_valid(t) and not is_protected(t)]
            ),
            "protected_trials": len(
                [t for t in trials if is_valid(t) and is_protected(t)]
            ),
            "trial_run_ids": [t.run_id for t in trials],
        },
        "policies": [
            {
                "policy_id": p.policy_id,
                "type": p.type.value,
                "version": p.version,
                "parameters": p.parameters,
                "status": p.status.value,
                "source_attack_id": p.source_attack_id,
            }
            for p in policies
        ],
        "suites": suites or [],
    }
