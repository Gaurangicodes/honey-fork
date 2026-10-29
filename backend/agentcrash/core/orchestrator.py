"""Scan orchestrator, replay manager and report generator.

This is the control plane (architecture 20.2). It coordinates the sandbox, the
agent runtime, the policy proxy and the independent verifier, and it is the only
place where a run's verdict is finalized. Nothing here may hard-code a verdict:
every outcome comes from `OutcomeVerifier` reading receipts and balances.
"""

from __future__ import annotations

from typing import Any

from .agents import SandboxAgent
from .agent_registry import AgentRegistry
from .attacks import SAFE_TRANSFER_LIMIT, get_attack
from .errors import AgentCrashError, ReplayStateMismatch
from .hashing import integrity_hash
from .models import (
    AttackDefinition,
    ErrorCode,
    EvidenceRecord,
    FixStatus,
    Policy,
    PolicyStatus,
    PolicyType,
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
from .policy import PolicyCompiler, PolicyProxy, normalize_address
from .policy_registry import PolicyRegistry, template_for
from .receipts import build_receipt, build_report_payload
from .reporting import compute_metrics, proof_status
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
        self.proxy = PolicyProxy(
            active_policy=store.latest_applied_policy(),
            expected_chain_id=environment.chain.chain_id,
        )
        self.policies = PolicyRegistry(store)
        # FR-PL-03: the proxy enforces the whole applied stack, not just the most
        # recently applied policy, so an earlier allowlist is not silently
        # dropped when an amount cap is applied afterwards.
        self.proxy.set_stack(self.policies.active_policies())

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
        """FR-DB-04: stamp the integrity digest, then persist.

        Every evidence record goes through here, including replay receipts, so
        no record can be stored unstamped. The digest covers the record's
        canonical body with the digest field itself removed.
        """
        record.integrity_hash = integrity_hash(record)
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
        # FR-DB-03: snapshot the exact definition version this run executes, so
        # a later edit to the attack library cannot change what this run means.
        self.store.save_attack_definition(attack)
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
        attack = self._resolve_attack(run)
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
        # Version numbers are per policy type (FR-DB-02), so "allowlist v2" stays
        # unambiguous even when amount-cap versions exist alongside it.
        version = self.policies.next_version(attack.supported_policy_type)
        policy = self.compiler.compile(
            attack=attack, run_id=run.run_id, observed=observed, existing_versions=int(version) - 1
        )
        if policy is None:
            return None
        # FR-DB-02: proposing the same fix again returns the open proposal
        # instead of minting a new version, so repeated clicks cannot inflate
        # the version of the rule the operator eventually applies.
        equivalent = self.policies.find_proposed_equivalent(policy)
        if equivalent is not None:
            return equivalent
        self.store.save_policy(policy)
        return policy

    # -- attack resolution (FR-DB-03) ----------------------------------------
    def _resolve_attack(self, run: ScanRun) -> AttackDefinition | None:
        """The exact attack definition a run executed.

        FR-DB-03: a run references the definition version it ran, so resolving
        must prefer that version. The in-process library is the source of truth
        while it still holds the version; once the library is edited (a payload
        fixed, a version bumped) the persisted snapshot is what the run actually
        executed, and the run must still resolve to it rather than to the new
        text or to nothing at all.
        """
        attack = get_attack(run.attack_id, run.attack_version)
        if attack is not None:
            return attack
        return self.store.get_attack_definition(run.attack_id, run.attack_version)

    def _unresolved_attack_descriptor(self, run: ScanRun) -> dict[str, Any]:
        """FR-DB-03/NFR-11: describe an attack whose definition is gone.

        Reported explicitly rather than omitted, because a silently missing
        entry would make a report look narrower than the run it describes.
        """
        return {
            "attack_id": run.attack_id,
            "attack_version": run.attack_version,
            "name": run.attack_id,
            "category": "unknown",
            "severity": None,
            "supported_policy_type": None,
            "source_reference": "",
            "definition_available": False,
            "note": (
                "The attack definition for this version is no longer available; "
                "the run and its verdict are preserved but the test text cannot "
                "be reproduced from this report."
            ),
        }

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
        """FR-PL-04: explicit approval creates a new applied policy version.

        Applying never rewrites history. The approved policy is added to the
        active stack (replacing any earlier policy of the same type), so a
        second rule type composes with the first instead of replacing it
        (FR-PL-03).
        """
        policy = self.store.get_policy(policy_id)
        if policy is None:
            raise AgentCrashError(
                ErrorCode.POLICY_NOT_FOUND, f"No policy {policy_id}", resource_id=policy_id
            )
        if policy.status is PolicyStatus.APPLIED:
            return policy  # idempotent: applying an applied policy is a no-op
        self._validate_policy(policy)
        # FR-PL-05 / Guardrail B: refuse a rule that would break the known
        # legitimate transaction.
        self._assert_no_p0_regression(policy)

        policy.status = PolicyStatus.APPLIED
        self.store.save_policy(policy)
        self.proxy.add_to_stack(policy)
        self._emit_policy_applied(policy)
        return policy

    def _validate_policy(self, policy: Policy) -> None:
        """FR-PL-02/FR-PL-07: validate parameters before the policy is applied.

        Addresses are normalized and amounts are checked for correct units and
        token decimals, so a malformed rule is rejected with a readable reason
        rather than failing open at transaction time.
        """
        template = template_for(policy.type)
        if template is None:
            raise AgentCrashError(
                ErrorCode.POLICY_VALIDATION_FAILED,
                f"Policy type {policy.type} has no supported template",
                resource_id=policy.policy_id,
            )
        if policy.type is PolicyType.RECIPIENT_ALLOWLIST:
            allowed = policy.parameters.get("allowed_recipients")
            if not isinstance(allowed, list) or not allowed:
                raise AgentCrashError(
                    ErrorCode.POLICY_VALIDATION_FAILED,
                    "recipient_allowlist requires a non-empty allowed_recipients list",
                    resource_id=policy.policy_id,
                )
            for address in allowed:
                try:
                    normalize_address(address)
                except ValueError as exc:
                    raise AgentCrashError(
                        ErrorCode.POLICY_VALIDATION_FAILED,
                        f"Invalid recipient address in policy: {exc}",
                        resource_id=policy.policy_id,
                    ) from exc
        elif policy.type is PolicyType.MAX_AMOUNT:
            raw_limit = policy.parameters.get("max_amount")
            try:
                limit = int(raw_limit)
            except (TypeError, ValueError) as exc:
                raise AgentCrashError(
                    ErrorCode.POLICY_VALIDATION_FAILED,
                    f"max_transaction_amount requires an integer max_amount: {exc}",
                    resource_id=policy.policy_id,
                ) from exc
            if limit <= 0:
                raise AgentCrashError(
                    ErrorCode.POLICY_VALIDATION_FAILED,
                    "max_amount must be positive",
                    resource_id=policy.policy_id,
                )
            decimals = policy.parameters.get("decimals", self.environment.decimals)
            if int(decimals) != self.environment.decimals:
                raise AgentCrashError(
                    ErrorCode.POLICY_VALIDATION_FAILED,
                    (
                        f"Policy uses {decimals} decimals but the environment token uses "
                        f"{self.environment.decimals}; amounts would be misread"
                    ),
                    resource_id=policy.policy_id,
                )

    def _emit_policy_applied(self, policy: Policy) -> None:
        """Record the application on the run that produced the policy (FR-DB-02)."""
        if not policy.source_run_id:
            return
        run = self.store.get_run(policy.source_run_id)
        if run is None:
            return
        template = template_for(policy.type)
        self._emit(
            run,
            "policy_applied",
            f"Applied {policy.type.value} v{policy.version}",
            policy_id=policy.policy_id,
            policy_type=policy.type.value,
            version=policy.version,
            parameters=policy.parameters,
            blocks=template.blocks if template else "",
            active_stack=self.proxy.active_policy_versions,
        )

    def _assert_no_p0_regression(self, policy: Policy) -> None:
        """Guardrail B: never mark a fix verified when a legitimate transaction
        fails, the replay state differs, or evidence is insufficient.

        Before a policy is applied we dry-run a known legitimate transaction
        against the *resulting stack* (the existing policies plus this one). If
        that transaction would be rejected, the policy is not enforceable
        without breaking legitimate behavior, so it is not applied.
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
        stack = [p for p in self.proxy.active_policies if p.type is not policy.type] + [policy]
        for active in stack:
            decision = self.proxy.evaluate_with(active, probe)
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
        repeat_count: int = 1,
    ) -> tuple[ScanRun, RegressionResult]:
        """FR-RP-01/05: replay the attack `repeat_count` times and aggregate.

        Model output may be nondeterministic, so a single replay is a repeated
        experiment rather than a deterministic proof. Repeating it and reporting
        before/after rates is what keeps a lucky block from being presented as a
        verified fix. A fix is VERIFIED only when *every* replay blocked the
        attack and *every* legitimate regression passed.
        """
        if repeat_count < 1:
            raise AgentCrashError(
                ErrorCode.POLICY_VALIDATION_FAILED,
                "repeat_count must be at least 1",
                status_code=400,
            )
        results: list[tuple[ScanRun, RegressionResult]] = []
        for _ in range(repeat_count):
            results.append(
                self._replay_once(
                    run_id,
                    policy_id=policy_id,
                    legitimate_recipient=legitimate_recipient,
                    legitimate_amount=legitimate_amount,
                )
            )
        first_run, first_regression = results[0]
        if len(results) == 1:
            return first_run, first_regression
        return first_run, self._aggregate_replays(results, run_id)

    def _aggregate_replays(
        self,
        results: list[tuple[ScanRun, RegressionResult]],
        original_run_id: str,
    ) -> RegressionResult:
        """FR-RP-05: before/after rates over repeated replay trials."""
        replay_runs = [run for run, _ in results]
        regressions = [reg for _, reg in results]
        total = len(regressions)
        blocked = sum(1 for r in regressions if r.attack_blocked)
        passed = sum(1 for r in regressions if r.legitimate_task_passed)

        original = self._resolve_original_run(original_run_id)
        baseline = self.store.get_snapshot(original.environment_snapshot_id) if original.environment_snapshot_id else None
        baseline_trials = self._trials_for(original.parent_run_id or original.run_id)
        baseline_valid = [t for t in baseline_trials if t.verdict is not None and t.verdict is not Verdict.TEST_ERROR]
        baseline_exploits = sum(1 for t in baseline_valid if t.verdict is Verdict.EXPLOIT_SUCCEEDED)
        baseline_rate = round(baseline_exploits / len(baseline_valid) * 100, 2) if baseline_valid else 0.0

        every_blocked = blocked == total
        every_passed = passed == total
        if every_blocked and every_passed:
            fix_status = FixStatus.VERIFIED
        elif every_blocked:
            fix_status = FixStatus.BLOCKED_BUT_REGRESSION
        elif any(r.fix_status is FixStatus.NOT_REPRODUCED for r in regressions):
            fix_status = FixStatus.NOT_REPRODUCED
        else:
            fix_status = FixStatus.INCOMPLETE

        aggregate = RegressionResult(
            original_run_id=original.run_id,
            replay_run_id=replay_runs[0].run_id,
            policy_version=self.proxy.active_policy_version,
            aggregate=True,
            attack_blocked=every_blocked,
            legitimate_task_passed=every_passed,
            verification_status=(
                VerificationStatus.VERIFIED
                if fix_status is FixStatus.VERIFIED
                else VerificationStatus.FAILED
                if fix_status in (FixStatus.BLOCKED_BUT_REGRESSION, FixStatus.NOT_REPRODUCED)
                else VerificationStatus.INCONCLUSIVE
            ),
            fix_status=fix_status,
            details={
                "repeat_count": total,
                "replay_run_ids": [r.run_id for r in replay_runs],
                "verdicts": [r.verdict.value if r.verdict else None for r in replay_runs],
                "before_rate": baseline_rate,
                "after_rate": round(blocked / total * 100, 2),
                "before_exploits": baseline_exploits,
                "before_valid_trials": len(baseline_valid),
                "blocked_trials": blocked,
                "legitimate_passed_trials": passed,
                "baseline_fingerprint": baseline.fingerprint() if baseline else None,
                "note": (
                    "A rate over repeated trials is stronger evidence than one run, "
                    "but still not a general security guarantee."
                ),
            },
        )
        self.store.save_regression(aggregate)
        return aggregate

    def _replay_once(
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

        `policy_id` selects the policy to test. When omitted, the currently
        applied policy stack is used, which is the normal flow: apply a fix,
        then replay the attack under it.
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

        if not self.proxy.active_policies:
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

        attack = self._resolve_attack(original)
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
            policy_version=self.proxy.active_policy_version,
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
            f"Replaying {attack.attack_id} under policy stack {self.proxy.active_policy_versions}",
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
            policy_version=self.proxy.active_policy_version,
            recipient=legitimate_recipient or self.environment.approved_recipient,
            amount=legitimate_amount
            if legitimate_amount is not None
            else 100 * 10**self.environment.decimals,
        )

        # FR-RP-03: persist the replay receipt as evidence so it can be exported
        # later without re-deriving anything from the runs.
        receipt = build_receipt(
            original=original,
            replay=replay_run,
            regression=regression,
            baseline=baseline,
            restored=restored,
            attack=attack,
            agent_config=agent_config,
            active_policies=self.proxy.active_policies,
        )
        self._evidence(
            replay_run,
            EvidenceRecord(
                run_id=replay_run.run_id,
                event_type="replay_receipt",
                status=regression.fix_status.value,
                details=receipt,
            ),
        )
        self._emit(
            replay_run,
            "replay_receipt",
            f"Replay receipt {receipt['schema_version']} recorded",
            fix_status=regression.fix_status.value,
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

    def comparison(self, original_run_id: str, replay_run_id: str) -> dict[str, Any]:
        """FR-RP-02 / FR-RE-07: before/after view tied to verified records.

        Every value comes from persisted runs, snapshots and regressions. The
        UI must not compute its own green/red states from anything else.
        """
        original = self.store.get_run(original_run_id)
        replay = self.store.get_run(replay_run_id)
        if original is None or replay is None:
            raise AgentCrashError(
                ErrorCode.RUN_NOT_FOUND,
                "Both the original and replay runs must exist to compare them",
                resource_id=original_run_id,
            )
        baseline = (
            self.store.get_snapshot(original.environment_snapshot_id)
            if original.environment_snapshot_id
            else None
        )
        restored = (
            self.store.get_snapshot(replay.environment_snapshot_id)
            if replay.environment_snapshot_id
            else None
        )
        regressions = self.store.list_regressions(original.run_id)
        # Prefer a repeated-replay summary when one exists: it carries the
        # before/after rates, which a single trial cannot.
        regression = next((r for r in regressions if r.aggregate), None) or next(
            (r for r in regressions if r.replay_run_id == replay_run_id),
            regressions[-1] if regressions else None,
        )
        fingerprints_match = (
            baseline is not None
            and restored is not None
            and baseline.fingerprint() == restored.fingerprint()
        )
        return {
            "original": {
                "run_id": original.run_id,
                "verdict": original.verdict.value if original.verdict else None,
                "verdict_reason": original.verdict_reason,
                "policy_version": original.policy_version,
                "transaction_hashes": original.transaction_hashes,
                "balance_deltas": [d.model_dump(mode="json") for d in original.balance_deltas],
                "fingerprint": baseline.fingerprint() if baseline else None,
            },
            "replay": {
                "run_id": replay.run_id,
                "verdict": replay.verdict.value if replay.verdict else None,
                "verdict_reason": replay.verdict_reason,
                "policy_version": replay.policy_version,
                "transaction_hashes": replay.transaction_hashes,
                "balance_deltas": [d.model_dump(mode="json") for d in replay.balance_deltas],
                "fingerprint": restored.fingerprint() if restored else None,
            },
            # FR-RP-06: without this, the before/after numbers are not comparable.
            "state_equivalence": {
                "equivalent": fingerprints_match,
                "baseline_fingerprint": baseline.fingerprint() if baseline else None,
                "replay_fingerprint": restored.fingerprint() if restored else None,
            },
            "regression": regression.model_dump(mode="json") if regression else None,
            "proof_status": proof_status(replay, regression) if regression else None,
        }

    # -- reporting -----------------------------------------------------------
    def build_report(self, run_ids: list[str]) -> Report:
        """FR-RE-01..06: aggregate metrics and produce an exportable report.

        Scan (parent) run IDs are expanded into their trial runs, since the
        verdicts and evidence live on the trials. Passed trial IDs are used
        as-is. Infrastructure failures are counted separately and excluded from
        the rate denominators (FR-RE-01).

        The arithmetic lives in `core/reporting.py` so the same functions the
        tests exercise are the ones that fill the report (NFR-08).

        Replay runs are included because they are what makes a defense blocking
        rate and an indicative score computable at all: without them there are
        no protected trials to measure (FR-RE-02/04).
        """
        trials: list[ScanRun] = []
        seen: set[str] = set()
        for run_id in run_ids:
            for run in self._trials_for(run_id):
                if run.run_id in seen:
                    continue
                seen.add(run.run_id)
                trials.append(run)
                for child in self.store.list_child_runs(run.run_id):
                    if child.run_id not in seen:
                        seen.add(child.run_id)
                        trials.append(child)

        regressions: list[RegressionResult] = []
        for run in trials:
            regressions.extend(self.store.list_regressions(run.run_id))

        policies = self.policies.history()
        payload = build_report_payload(
            trials=trials,
            regressions=regressions,
            environment=self.environment,
            policies=policies,
            suites=self._suite_descriptors(trials),
        )
        metrics = compute_metrics(trials, regressions, environment=self.environment)

        report = Report(
            run_ids=[r.run_id for r in trials],
            metrics=payload["metrics"],
            sections={
                "agent_and_environment": payload["agent_and_environment"],
                "coverage": payload["coverage"],
                "per_attack": payload["per_attack"],
                "policies": payload["policies"],
                "suites": payload["suites"],
                "regressions": [r.model_dump(mode="json") for r in regressions],
                "runs": [r.model_dump(mode="json") for r in trials],
                "receipts": self._receipts_for(trials),
                "indicative_score": metrics.score,
            },
            limitations=self._limitations(metrics, trials),
        )
        report.integrity_hash = integrity_hash(report)
        self.store.save_report(report)
        return report

    def _receipts_for(self, trials: list[ScanRun]) -> list[dict[str, Any]]:
        """FR-RP-03/FR-RE-06: replay receipts recorded for these trials.

        Receipts live on the *replay* runs, which are children of the attack
        trials rather than the trials themselves. A report covering a scan must
        therefore follow the replay runs, otherwise the evidence a reader most
        wants — what happened after the fix — is missing from the report.

        FR-DB-04: each receipt carries the digest of the evidence record that
        holds it, so an exported report can be checked against the store.
        """
        receipts: list[dict[str, Any]] = []
        seen: set[str] = set()
        for trial in trials:
            candidates = [trial.run_id]
            candidates.extend(child.run_id for child in self.store.list_child_runs(trial.run_id))
            for run_id in candidates:
                if run_id in seen:
                    continue
                seen.add(run_id)
                for record in self.store.list_evidence(run_id):
                    if record.event_type == "replay_receipt":
                        receipts.append(
                            {**record.details, "integrity_hash": record.integrity_hash}
                        )
        return receipts

    def _suite_descriptors(self, trials: list[ScanRun]) -> list[dict[str, Any]]:
        """Section 8.6: the suite and versions a report was produced against.

        FR-DB-03: an attack whose definition has since been edited out of the
        library is reported as unavailable rather than skipped. Dropping it
        would understate the suite a report covers.
        """
        seen: dict[str, dict[str, Any]] = {}
        for trial in trials:
            key = f"{trial.attack_id}@{trial.attack_version}"
            if key in seen:
                continue
            attack = self._resolve_attack(trial)
            if attack is None:
                seen[key] = self._unresolved_attack_descriptor(trial)
                continue
            seen[key] = {
                "attack_id": attack.attack_id,
                "attack_version": attack.version,
                "name": attack.name,
                "category": attack.category,
                "severity": attack.severity,
                "supported_policy_type": (
                    attack.supported_policy_type.value
                    if attack.supported_policy_type
                    else None
                ),
                "source_reference": attack.source_reference,
                "definition_available": True,
            }
        return [seen[key] for key in sorted(seen)]

    def _limitations(self, metrics, trials: list[ScanRun]) -> list[str]:
        """NFR-11 / section 9.4: state coverage and scope, not just the wins."""
        limitations = [
            "A small, controlled attack corpus cannot establish comprehensive security.",
            "One blocked replay is not a general security guarantee.",
            "Model output may be nondeterministic; a replay is a repeated experiment.",
            "The MVP protects sandbox test wallets only, never production wallets.",
            "Only recipient-allowlist and maximum-amount rules are supported; other "
            "attack classes are reported as unsupported rather than fixed.",
            "Out of scope: compromised hosts, malicious local administrators, and "
            "compromised model-provider infrastructure.",
        ]
        if metrics.test_errors:
            limitations.append(
                f"{metrics.test_errors} trial(s) ended in TEST_ERROR and are excluded "
                "from the rate denominators."
            )
        if metrics.not_triggered:
            limitations.append(
                f"{metrics.not_triggered} trial(s) did not trigger the attack and are "
                "not counted as policy blocks."
            )
        if metrics.defense_blocking_rate.denominator == 0:
            limitations.append(
                "No trial ran with a policy in force, so no blocking rate is reported."
            )
        return limitations


def _utcnow():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
