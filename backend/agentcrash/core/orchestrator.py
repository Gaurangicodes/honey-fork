"""Scan orchestrator, replay manager and report generator.

This is the control plane (architecture 20.2). It coordinates the sandbox, the
agent runtime, the policy proxy and the independent verifier, and it is the only
place where a run's verdict is finalized. Nothing here may hard-code a verdict:
every outcome comes from `OutcomeVerifier` reading receipts and balances.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .agents import SandboxAgent
from .agent_registry import AgentRegistry
from .attacks import SAFE_TRANSFER_LIMIT, get_attack
from .errors import AgentCrashError, ReplayStateMismatch
from .models import (
    ErrorCode,
    EvidenceRecord,
    FixStatus,
    Policy,
    PolicyStatus,
    RegressionResult,
    Report,
    RunEvent,
    RunStatus,
    RunType,
    ScanRun,
    Verdict,
    VerificationStatus,
    WalletAction,
)
from .policy import PolicyCompiler, PolicyProxy
from .store import Store
from .tools import ToolRegistry
from .wallet import execute_wallet_action
from ..sandbox.manager import SandboxEnvironment, SandboxManager
from ..sandbox.verifier import OutcomeVerifier, error_result


class Orchestrator:
    def __init__(
        self,
        store: Store,
        environment: SandboxEnvironment,
        manager: SandboxManager,
        compiler: PolicyCompiler | None = None,
        agents: AgentRegistry | None = None,
        tools: ToolRegistry | None = None,
    ) -> None:
        self.store = store
        self.environment = environment
        self.manager = manager
        self.compiler = compiler or PolicyCompiler()
        self.tools = tools or ToolRegistry()
        self.agents = agents or AgentRegistry(tools=self.tools)
        self.verifier = OutcomeVerifier(
            unauthorized_recipient=environment.unauthorized_recipient,
            token_contract=environment.token_contract,
        )
        self.proxy = PolicyProxy(active_policy=store.latest_applied_policy())

    # -- helpers -------------------------------------------------------------
    def _emit(self, run: ScanRun, event_type: str, message: str, **data: Any) -> RunEvent:
        events = self.store.list_events(run.run_id)
        event = RunEvent(
            run_id=run.run_id,
            seq=len(events) + 1,
            event_type=event_type,
            message=message,
            data=data,
        )
        self.store.save_event(event)
        return event

    def _evidence(self, run: ScanRun, record: EvidenceRecord) -> None:
        canonical = record.model_dump(mode="json")
        canonical.pop("integrity_hash", None)
        record.integrity_hash = "0x" + hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.store.save_evidence(record)

    # -- attack runs ---------------------------------------------------------
    def start_scan(self, agent_id: str, attack_ids: list[str], repeat_count: int) -> ScanRun:
        """FR-UI-02: validate, then run each attack `repeat_count` times."""
        agent = self.agents.get(agent_id)
        if agent is None:
            raise AgentCrashError(
                ErrorCode.AGENT_NOT_FOUND, f"Unknown agent {agent_id}", resource_id=agent_id
            )
        attacks = []
        for attack_id in attack_ids:
            attack = get_attack(attack_id)
            if attack is None:
                raise AgentCrashError(
                    ErrorCode.ATTACK_NOT_FOUND,
                    f"Unknown attack {attack_id}",
                    resource_id=attack_id,
                )
            attacks.append(attack)

        first = attacks[0]
        parent = ScanRun(
            agent_id=agent_id,
            attack_id=first.attack_id,
            run_type=RunType.ATTACK,
            status=RunStatus.QUEUED,
            policy_version=self.proxy.active_policy_version,
            repeat_count=repeat_count,
            environment_id=self.environment.environment_id,
        )
        self.store.save_run(parent)
        self._emit(parent, "scan_started", f"Scan started for {len(attacks)} attack(s)")
        return parent

    def run_attack_trials(
        self, parent_run: ScanRun, attack_ids: list[str]
    ) -> list[ScanRun]:
        """Run every trial and finalize the parent run status.

        Kept separate from `start_scan` so the API can return a run id
        immediately and the work can proceed in the background.
        """
        agent_config = self.agents.get(parent_run.agent_id)
        assert agent_config is not None  # validated in start_scan
        trials: list[ScanRun] = []
        try:
            parent_run.status = RunStatus.RUNNING
            self.store.save_run(parent_run)
            for attack_id in attack_ids:
                attack = get_attack(attack_id)
                assert attack is not None
                for trial_index in range(1, parent_run.repeat_count + 1):
                    trial = self._run_single_trial(
                        parent=parent_run, attack=attack, trial_index=trial_index
                    )
                    trials.append(trial)
            parent_run.status = RunStatus.COMPLETED
            parent_run.finished_at = trials[-1].finished_at if trials else None
        except Exception as exc:  # infrastructure failure -> error status, never a verdict
            parent_run.status = RunStatus.FAILED
            parent_run.error_code = ErrorCode.SANDBOX_UNAVAILABLE.value
            parent_run.error_message = str(exc)
            self._emit(parent_run, "scan_failed", f"Scan failed: {exc}")
        self.store.save_run(parent_run)
        return trials

    def _run_single_trial(self, *, parent: ScanRun, attack, trial_index: int) -> ScanRun:
        agent_config = self.agents.get(parent.agent_id)
        assert agent_config is not None
        enforce = agent_config.guardrail == "policy_proxy"

        trial = ScanRun(
            agent_id=parent.agent_id,
            attack_id=attack.attack_id,
            parent_run_id=parent.run_id,
            run_type=RunType.ATTACK,
            status=RunStatus.RUNNING,
            policy_version=self.proxy.active_policy_version,
            trial_index=trial_index,
            repeat_count=parent.repeat_count,
            attack_version=attack.version,
            agent_config_version=agent_config.configuration_version,
            environment_id=self.environment.environment_id,
        )
        self.store.save_run(trial)
        self._emit(
            trial,
            "payload_received",
            f"Delivered untrusted input for {attack.attack_id}",
            attack_id=attack.attack_id,
            attack_version=attack.version,
        )

        # FR-SB-01/02: known state, then capture the fingerprint.
        self.manager.reset()
        before = self.manager.capture_state(
            run_id=trial.run_id,
            policy_version=self.proxy.active_policy_version,
            attack_id=attack.attack_id,
        )
        trial.environment_snapshot_id = before.snapshot_id
        self.store.save_snapshot(before)

        agent = SandboxAgent(agent_config, self.tools)
        try:
            # FR-AT-05: reach the payload through the registered tools only, so a
            # malicious-tool scenario runs a controlled mock. Observations are
            # recorded as evidence, including any rejected (unregistered) call.
            observations = agent.gather_observations(attack)
            for observation in observations:
                trial.tool_calls.append(
                    {
                        "tool": observation.tool_id,
                        "arguments": observation.arguments,
                        "ok": observation.ok,
                        "rejected": observation.rejected,
                        "rejection_reason": observation.rejection_reason,
                    }
                )
                self._emit(
                    trial,
                    "tool_result_rejected" if observation.rejected else "tool_result",
                    (
                        observation.rejection_reason
                        if observation.rejected
                        else f"{observation.tool_id} returned an observation"
                    ),
                    tool=observation.tool_id,
                    ok=observation.ok,
                    rejected=observation.rejected,
                    output=observation.output,
                )
            action = agent.propose_action(
                attack,
                sender=self.environment.agent_address,
                token=self.environment.token_contract,
                chain_id=self.environment.chain.chain_id,
                unauthorized_recipient=self.environment.unauthorized_recipient,
                decimals=self.environment.decimals,
                observations=observations,
            )
        except Exception as exc:
            return self._finalize_error(trial, before, f"Agent runtime error: {exc}")

        attack_triggered = action is not None
        receipts = []
        policy_blocked = False

        if action is not None:
            trial.tool_calls.append(
                {"tool": "wallet.transfer", "arguments": action.model_dump(mode="json")}
            )
            self._emit(
                trial,
                "tool_call",
                "Agent proposed wallet.transfer",
                arguments=action.model_dump(mode="json"),
            )
            result = execute_wallet_action(
                action, chain=self.environment.chain, proxy=self.proxy, enforce=enforce
            )
            self._emit(
                trial,
                "policy_decision",
                result.decision.reason,
                allowed=result.decision.allowed,
                reason_code=result.decision.reason_code,
                policy_version=result.decision.policy_version,
                enforce=enforce,
            )
            if not result.decision.allowed:
                policy_blocked = True
            if result.receipt is not None:
                receipts.append(result.receipt)
                trial.transaction_hashes.append(result.receipt.tx_hash)
                self._emit(
                    trial,
                    "transaction_receipt",
                    f"Transaction {result.receipt.status} in block {result.receipt.block_number}",
                    **result.receipt.to_dict(),
                )
        else:
            self._emit(
                trial,
                "agent_no_action",
                "Agent produced no wallet action for this payload",
            )

        after_deltas = self.manager.balance_deltas(before)
        trial.balance_deltas = after_deltas

        verification = self.verifier.verify(
            attack=attack,
            before=before,
            deltas=after_deltas,
            receipts=receipts,
            policy_blocked=policy_blocked,
            attack_triggered=attack_triggered,
        )
        trial.verdict = verification.verdict
        trial.verdict_reason = verification.reason
        trial.status = RunStatus.COMPLETED
        trial.finished_at = _utcnow()
        self.store.save_run(trial)

        self._evidence(
            trial,
            EvidenceRecord(
                run_id=trial.run_id,
                event_type="verdict",
                transaction_hash=receipts[-1].tx_hash if receipts else None,
                status=trial.verdict.value,
                block_number=receipts[-1].block_number if receipts else None,
                before_state=before.model_dump(mode="json"),
                after_state={"balances": {d.address: d.after for d in after_deltas}},
                details=verification.to_dict(),
            ),
        )
        self._emit(trial, "verifier_verdict", verification.reason, verdict=trial.verdict.value)
        return trial

    def _finalize_error(self, trial: ScanRun, before, reason: str) -> ScanRun:
        """TEST_ERROR: infrastructure failure, never reported as a security result.

        Routed through the verifier's `error_result` helper so that every verdict
        in the system, including failures, originates from one place.
        """
        result = error_result(reason, self.manager.balance_deltas(before))
        trial.verdict = result.verdict
        trial.verdict_reason = result.reason
        trial.balance_deltas = result.deltas
        trial.status = RunStatus.FAILED
        trial.error_code = ErrorCode.MODEL_PROVIDER_ERROR.value
        trial.error_message = reason
        trial.finished_at = _utcnow()
        self.store.save_run(trial)
        self._emit(trial, "test_error", reason)
        return trial

    # -- policy --------------------------------------------------------------
    def propose_policies(self, run_id: str) -> list[Policy]:
        """FR-PL-01: map each verified exploit in a scan to a supported policy.

        `run_id` may be a scan (parent) or a single trial. For a scan, one policy
        is proposed per verified exploit, so a suite mixing a recipient violation
        with an amount violation yields both templates.
        """
        policies: list[Policy] = []
        for trial in self._trials_for(run_id):
            if trial.verdict is not Verdict.EXPLOIT_SUCCEEDED:
                continue
            policy = self._propose_for_run(trial)
            if policy is not None:
                policies.append(policy)
        return policies

    def propose_policy(self, run_id: str) -> Policy | None:
        """Convenience wrapper returning the first proposed policy, if any."""
        policies = self.propose_policies(run_id)
        return policies[0] if policies else None

    def _propose_for_run(self, run: ScanRun) -> Policy | None:
        attack = get_attack(run.attack_id, run.attack_version)
        if attack is None:
            raise AgentCrashError(
                ErrorCode.ATTACK_NOT_FOUND, f"No attack {run.attack_id}", resource_id=run.attack_id
            )
        observed = {
            "approved_recipient": self.environment.approved_recipient,
            "unauthorized_recipient": self.environment.unauthorized_recipient,
            "suggested_limit": SAFE_TRANSFER_LIMIT,
            "decimals": self.environment.decimals,
        }
        existing = [p for p in self.store.list_policies() if p.source_attack_id == attack.attack_id]
        policy = self.compiler.compile(
            attack=attack, run_id=run.run_id, observed=observed, existing_versions=len(existing)
        )
        if policy is not None:
            self.store.save_policy(policy)
        return policy

    # -- run resolution ------------------------------------------------------
    def _trials_for(self, run_id: str) -> list[ScanRun]:
        """Return the trial runs for `run_id`.

        A scan (parent) run carries no verdict of its own; its trials do. When
        `run_id` already denotes a trial, the trial itself is returned.
        """
        run = self.store.get_run(run_id)
        if run is None:
            raise AgentCrashError(ErrorCode.RUN_NOT_FOUND, f"No run {run_id}", resource_id=run_id)
        children = self.store.list_child_runs(run_id)
        return children if children else [run]

    def _resolve_original_run(self, run_id: str) -> ScanRun:
        """Pick the run a replay should reproduce.

        A scan is replayed by reproducing its verified exploit trial, since that
        is the run with an initial-state snapshot and an EXPLOIT_SUCCEEDED
        verdict. A trial id is returned unchanged.
        """
        run = self.store.get_run(run_id)
        if run is None:
            raise AgentCrashError(ErrorCode.RUN_NOT_FOUND, f"No run {run_id}", resource_id=run_id)
        if run.environment_snapshot_id:
            return run
        children = [c for c in self.store.list_child_runs(run_id) if c.environment_snapshot_id]
        exploits = [c for c in children if c.verdict is Verdict.EXPLOIT_SUCCEEDED]
        if exploits:
            return exploits[0]
        if children:
            return children[0]
        return run

    def apply_policy(self, policy_id: str) -> Policy:
        """FR-PL-04: explicit approval creates a new applied policy version."""
        policy = self.store.get_policy(policy_id)
        if policy is None:
            raise AgentCrashError(
                ErrorCode.POLICY_NOT_FOUND, f"No policy {policy_id}", resource_id=policy_id
            )
        self._assert_no_p0_regression(policy)
        policy.status = PolicyStatus.APPLIED
        self.store.save_policy(policy)
        self.proxy.set_active_policy(policy)
        return policy

    def _assert_no_p0_regression(self, policy: Policy) -> None:
        """Guardrail B: never mark a fix verified when a legitimate transaction
        fails, the replay state differs, or evidence is insufficient.

        Before a policy is applied we dry-run a known legitimate transaction
        against it. If that transaction would be rejected, the policy is not
        enforceable without breaking legitimate behavior, so it is not applied.
        """
        probe = WalletAction(
            action_type="transfer",
            token=self.environment.token_contract,
            chain_id=self.environment.chain.chain_id,
            sender=self.environment.agent_address,
            recipient=self.environment.approved_recipient,
            amount=100 * 10 ** self.environment.decimals,
            decimals=self.environment.decimals,
            source="regression",
        )
        decision = self.proxy.evaluate_with(policy, probe)
        if not decision.allowed:
            raise AgentCrashError(
                ErrorCode.POLICY_VALIDATION_FAILED,
                (
                    f"Policy {policy.policy_id} would block a legitimate transfer "
                    f"({decision.reason_code}). It was not applied."
                ),
                resource_id=policy.policy_id,
            )

    # -- replay --------------------------------------------------------------
    def replay(
        self,
        run_id: str,
        *,
        policy_id: str | None = None,
        legitimate_recipient: str | None = None,
        legitimate_amount: int | None = None,
    ) -> tuple[ScanRun, RegressionResult]:
        """FR-RP-01..06: equivalent-state replay plus legitimate regression.

        `run_id` may be a scan or a trial; the original trial that produced the
        verified exploit is selected automatically.
        """
        original = self._resolve_original_run(run_id)
        if original.environment_snapshot_id is None:
            raise AgentCrashError(
                ErrorCode.RUN_NOT_FOUND,
                f"Run {original.run_id} has no recorded initial state to replay",
                resource_id=original.run_id,
            )

        if policy_id is not None:
            self.apply_policy(policy_id)
        active = self.proxy.active_policy
        if active is None:
            raise AgentCrashError(
                ErrorCode.POLICY_VALIDATION_FAILED,
                "Replay requires an applied policy",
                status_code=400,
            )

        baseline = (
            self.store.get_snapshot(original.environment_snapshot_id)
            if original.environment_snapshot_id
            else None
        )
        if baseline is None:
            raise ReplayStateMismatch("Original run has no recorded initial-state snapshot")

        # FR-RP-06: restore equivalent state and compare the fingerprint.
        self.manager.reset()
        restored = self.manager.restore(baseline)
        if restored.fingerprint() != baseline.fingerprint():
            raise ReplayStateMismatch(
                "Restored state fingerprint does not match the original baseline"
            )

        attack = get_attack(original.attack_id, original.attack_version)
        if attack is None:
            raise AgentCrashError(
                ErrorCode.ATTACK_NOT_FOUND, f"No attack {original.attack_id}"
            )
        agent_config = self.agents.get(original.agent_id)
        assert agent_config is not None

        replay_run = ScanRun(
            agent_id=original.agent_id,
            attack_id=original.attack_id,
            parent_run_id=original.run_id,
            run_type=RunType.REPLAY,
            status=RunStatus.RUNNING,
            policy_version=active.version,
            attack_version=attack.version,
            agent_config_version=agent_config.configuration_version,
            environment_id=self.environment.environment_id,
        )
        self.store.save_run(replay_run)
        self.store.save_snapshot(restored)
        replay_run.environment_snapshot_id = restored.snapshot_id
        self._emit(
            replay_run,
            "replay_started",
            f"Replaying {attack.attack_id} under policy v{active.version}",
            fingerprint=restored.fingerprint(),
        )

        agent = SandboxAgent(agent_config, self.tools)
        observations = agent.gather_observations(attack)
        for observation in observations:
            replay_run.tool_calls.append(
                {
                    "tool": observation.tool_id,
                    "arguments": observation.arguments,
                    "ok": observation.ok,
                    "rejected": observation.rejected,
                    "rejection_reason": observation.rejection_reason,
                }
            )
        action = agent.propose_action(
            attack,
            sender=self.environment.agent_address,
            token=self.environment.token_contract,
            chain_id=self.environment.chain.chain_id,
            unauthorized_recipient=self.environment.unauthorized_recipient,
            decimals=self.environment.decimals,
            observations=observations,
        )
        attack_triggered = action is not None
        receipts = []
        policy_blocked = False
        if action is not None:
            replay_run.tool_calls.append(
                {"tool": "wallet.transfer", "arguments": action.model_dump(mode="json")}
            )
            result = execute_wallet_action(
                action, chain=self.environment.chain, proxy=self.proxy, enforce=True
            )
            self._emit(
                replay_run,
                "policy_decision",
                result.decision.reason,
                allowed=result.decision.allowed,
                reason_code=result.decision.reason_code,
                policy_version=result.decision.policy_version,
            )
            if not result.decision.allowed:
                policy_blocked = True
            if result.receipt is not None:
                receipts.append(result.receipt)
                replay_run.transaction_hashes.append(result.receipt.tx_hash)

        after_deltas = self.manager.balance_deltas(restored)
        replay_run.balance_deltas = after_deltas
        verification = self.verifier.verify(
            attack=attack,
            before=restored,
            deltas=after_deltas,
            receipts=receipts,
            policy_blocked=policy_blocked,
            attack_triggered=attack_triggered,
        )
        replay_run.verdict = verification.verdict
        replay_run.verdict_reason = verification.reason
        replay_run.status = RunStatus.COMPLETED
        replay_run.finished_at = _utcnow()
        self.store.save_run(replay_run)
        self._emit(
            replay_run, "verifier_verdict", verification.reason, verdict=replay_run.verdict.value
        )

        # FR-PL-05: a legitimate transaction must still succeed under the policy.
        regression = self._run_legitimate_regression(
            original_run=original,
            replay_run=replay_run,
            policy_version=active.version,
            recipient=legitimate_recipient or self.environment.approved_recipient,
            amount=legitimate_amount
            if legitimate_amount is not None
            else 100 * 10**self.environment.decimals,
        )
        return replay_run, regression

    def _run_legitimate_regression(
        self,
        *,
        original_run: ScanRun,
        replay_run: ScanRun,
        policy_version: str,
        recipient: str,
        amount: int,
    ) -> RegressionResult:
        before = self.manager.capture_state(
            run_id=replay_run.run_id,
            policy_version=policy_version,
            attack_id=None,
        )
        action = WalletAction(
            action_type="transfer",
            token=self.environment.token_contract,
            chain_id=self.environment.chain.chain_id,
            sender=self.environment.agent_address,
            recipient=recipient,
            amount=amount,
            decimals=self.environment.decimals,
            source="regression",
        )
        result = execute_wallet_action(
            action, chain=self.environment.chain, proxy=self.proxy, enforce=True
        )
        deltas = self.manager.balance_deltas(before)
        recipient_delta = next(
            (d.delta for d in deltas if d.address.lower() == recipient.lower()), 0
        )
        legitimate_passed = result.submitted and result.receipt is not None and recipient_delta > 0

        attack_blocked = replay_run.verdict is Verdict.ATTEMPT_BLOCKED
        if replay_run.verdict is Verdict.EXPLOIT_SUCCEEDED:
            fix_status = FixStatus.NOT_REPRODUCED
        elif replay_run.verdict is Verdict.TEST_ERROR:
            fix_status = FixStatus.TEST_ERROR
        elif replay_run.verdict is Verdict.ATTACK_NOT_TRIGGERED:
            fix_status = FixStatus.INCOMPLETE
        elif attack_blocked and legitimate_passed:
            fix_status = FixStatus.VERIFIED
        elif attack_blocked:
            fix_status = FixStatus.BLOCKED_BUT_REGRESSION
        else:
            fix_status = FixStatus.INCOMPLETE

        regression = RegressionResult(
            original_run_id=original_run.run_id,
            replay_run_id=replay_run.run_id,
            policy_version=policy_version,
            attack_blocked=attack_blocked,
            legitimate_task_passed=legitimate_passed,
            verification_status=(
                VerificationStatus.VERIFIED
                if fix_status is FixStatus.VERIFIED
                else VerificationStatus.FAILED
                if fix_status in (FixStatus.BLOCKED_BUT_REGRESSION, FixStatus.NOT_REPRODUCED)
                else VerificationStatus.INCONCLUSIVE
            ),
            fix_status=fix_status,
            details={
                "legitimate_action": action.model_dump(mode="json"),
                "policy_decision": result.decision.model_dump(mode="json"),
                "receipt": result.receipt.to_dict() if result.receipt else None,
                "balance_deltas": [d.model_dump(mode="json") for d in deltas],
                "replay_verdict": replay_run.verdict.value if replay_run.verdict else None,
            },
        )
        self.store.save_regression(regression)
        self._emit(
            replay_run,
            "regression_result",
            "Legitimate transfer passed" if legitimate_passed else "Legitimate transfer failed",
            fix_status=fix_status.value,
        )
        return regression

    # -- reporting -----------------------------------------------------------
    def build_report(self, run_ids: list[str]) -> Report:
        """FR-RE-01..06: aggregate metrics and produce an exportable report.

        Scan (parent) run IDs are expanded into their trial runs, since the
        verdicts and evidence live on the trials. Passed trial IDs are used
        as-is. Infrastructure failures are counted separately and excluded from
        the rate denominators (FR-RE-01).
        """
        trials: list[ScanRun] = []
        for run_id in run_ids:
            trials.extend(self._trials_for(run_id))
        valid = [r for r in trials if r.verdict is not None and r.verdict is not Verdict.TEST_ERROR]
        exploits = [r for r in valid if r.verdict is Verdict.EXPLOIT_SUCCEEDED]
        blocked = [r for r in valid if r.verdict is Verdict.ATTEMPT_BLOCKED]
        errors = [r for r in trials if r.verdict is Verdict.TEST_ERROR]

        asr = (len(exploits) / len(valid) * 100) if valid else 0.0
        dbr = (len(blocked) / len(valid) * 100) if valid else 0.0

        regressions: list[RegressionResult] = []
        for run in trials:
            regressions.extend(self.store.list_regressions(run.run_id))
        legitimate_total = len(regressions)
        legitimate_passed = sum(1 for r in regressions if r.legitimate_task_passed)
        legitimate_rate = (
            legitimate_passed / legitimate_total * 100 if legitimate_total else 0.0
        )

        report = Report(
            run_ids=[r.run_id for r in trials],
            metrics={
                "attack_success_rate": {
                    "value": round(asr, 2),
                    "numerator": len(exploits),
                    "denominator": len(valid),
                },
                "defense_blocking_rate": {
                    "value": round(dbr, 2),
                    "numerator": len(blocked),
                    "denominator": len(valid),
                },
                "legitimate_task_success_rate": {
                    "value": round(legitimate_rate, 2),
                    "numerator": legitimate_passed,
                    "denominator": legitimate_total,
                },
                "test_errors": len(errors),
            },
            sections={
                "runs": [r.model_dump(mode="json") for r in trials],
                "regressions": [r.model_dump(mode="json") for r in regressions],
                "environment": self.environment.environment_id,
            },
            limitations=[
                "A small, controlled attack corpus cannot establish comprehensive security.",
                "One blocked replay is not a general security guarantee.",
                "Model output may be nondeterministic; replay is a repeated experiment.",
                "The MVP protects sandbox test wallets only, never production wallets.",
            ],
        )
        canonical = report.model_dump(mode="json")
        canonical.pop("integrity_hash", None)
        report.integrity_hash = "0x" + hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.store.save_report(report)
        return report


def _utcnow():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
