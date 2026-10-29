"""Module 4 tests: replay, regression, scoring, receipts and reporting.

These exercise real code paths — a real orchestrator, a real SQLite store and
the real deterministic sandbox — rather than mocks. The metric functions are
pure, so they are also tested directly with hand-built run records.
"""

from __future__ import annotations

import json

import pytest

from agentcrash.core import reporting
from agentcrash.core.attacks import SAFE_TRANSFER_LIMIT
from agentcrash.core.models import (
    FixStatus,
    Policy,
    PolicyType,
    RegressionResult,
    ScanRun,
    Verdict,
    VerificationStatus,
)
from agentcrash.core.orchestrator import Orchestrator
from agentcrash.core.store import Store
from agentcrash.sandbox.manager import SandboxManager, default_demo_environment


@pytest.fixture()
def orchestrator(tmp_path):
    environment = default_demo_environment()
    store = Store(str(tmp_path / "module4.db"))
    return Orchestrator(store, environment, SandboxManager(environment))


def _run(verdict, policy_version=None, attack_id="AT-01", run_id=None):
    run = ScanRun(agent_id="agent-vulnerable-01", attack_id=attack_id)
    run.verdict = verdict
    run.policy_version = policy_version
    if run_id:
        run.run_id = run_id
    return run


# -- FR-RE-01 / FR-RE-02: rates always carry their denominator --------------
def test_asr_reports_numerator_and_denominator():
    trials = [
        _run(Verdict.EXPLOIT_SUCCEEDED),
        _run(Verdict.EXPLOIT_SUCCEEDED),
        _run(Verdict.ATTACK_NOT_TRIGGERED),
        _run(Verdict.TEST_ERROR),
    ]
    metrics = reporting.compute_metrics(trials, [])
    asr = metrics.attack_success_rate
    assert asr.numerator == 2
    # TEST_ERROR is excluded from the denominator (FR-RE-01).
    assert asr.denominator == 3
    assert asr.value == pytest.approx(66.67, abs=0.01)
    assert metrics.test_errors == 1


def test_asr_is_zero_without_division_error_when_no_valid_trials():
    metrics = reporting.compute_metrics([_run(Verdict.TEST_ERROR)], [])
    assert metrics.attack_success_rate.value == 0.0
    assert metrics.attack_success_rate.denominator == 0


def test_dbr_denominator_counts_only_protected_trials():
    """FR-RE-02: an unprotected baseline must not dilute the blocking rate."""
    trials = [
        _run(Verdict.EXPLOIT_SUCCEEDED),  # baseline, no policy
        _run(Verdict.ATTEMPT_BLOCKED, policy_version="1"),
        _run(Verdict.ATTEMPT_BLOCKED, policy_version="1"),
    ]
    metrics = reporting.compute_metrics(trials, [])
    dbr = metrics.defense_blocking_rate
    assert dbr.numerator == 2
    assert dbr.denominator == 2  # not 3
    assert dbr.value == 100.0


def test_untriggered_attack_is_not_counted_as_blocked():
    """Guardrail: an attack that never fired is not a policy block."""
    trials = [_run(Verdict.ATTACK_NOT_TRIGGERED, policy_version="1")]
    metrics = reporting.compute_metrics(trials, [])
    assert metrics.defense_blocking_rate.numerator == 0
    assert metrics.not_triggered == 1


def test_guarded_agent_without_an_applied_policy_is_not_protected():
    """A policy proxy with no policy in force blocks nothing."""
    trial = _run(Verdict.EXPLOIT_SUCCEEDED, policy_version=None)
    assert reporting.is_protected(trial) is False


# -- FR-RE-03: legitimate-task success ------------------------------------
def test_legitimate_task_success_rate():
    regressions = [
        RegressionResult(original_run_id="r1", legitimate_task_passed=True),
        RegressionResult(original_run_id="r2", legitimate_task_passed=False),
    ]
    metrics = reporting.compute_metrics([], regressions)
    rate = metrics.legitimate_task_success_rate
    assert rate.numerator == 1 and rate.denominator == 2
    assert rate.value == 50.0


# -- FR-RE-04: indicative score -------------------------------------------
def test_score_unavailable_without_both_halves_of_the_evidence():
    metrics = reporting.compute_metrics([_run(Verdict.EXPLOIT_SUCCEEDED)], [])
    score = metrics.score
    assert score["available"] is False
    assert score["value"] is None
    assert "formula" in score


def test_score_is_documented_and_bounded():
    dbr = reporting.Rate("dbr", 4, 4)
    ltsr = reporting.Rate("ltsr", 1, 1)
    score = reporting.indicative_score(dbr, ltsr)
    assert score["available"] is True
    assert score["value"] == 100.0
    assert "indicative" in score["label"]
    # Weights are disclosed so a reader can recompute the number.
    assert "60" in score["formula"] and "40" in score["formula"]


def test_score_penalises_a_regression():
    dbr = reporting.Rate("dbr", 4, 4)
    ltsr = reporting.Rate("ltsr", 0, 1)
    assert reporting.indicative_score(dbr, ltsr)["value"] == 60.0


# -- FR-RE-05: exposure is a scenario, not a prediction -------------------
def test_exposure_is_labelled_as_a_scenario():
    environment = default_demo_environment()
    exposure = reporting.estimated_exposure([], environment)
    assert exposure["observed_max_single_loss"] == "0"
    assert exposure["token"] == "TST"
    assert any("not a prediction" in a for a in exposure["assumptions"])


def test_exposure_reports_the_largest_observed_loss():
    environment = default_demo_environment()
    from agentcrash.core.models import BalanceDelta

    trial = _run(Verdict.EXPLOIT_SUCCEEDED)
    trial.balance_deltas = [
        BalanceDelta(
            address=environment.agent_address,
            token=environment.token_contract,
            before=1000,
            after=0,
            delta=-1000,
        )
    ]
    exposure = reporting.estimated_exposure([trial], environment)
    assert exposure["observed_max_single_loss"] == "0.000000000000001"


# -- FR-RE-07: proof status ------------------------------------------------
def test_proof_status_label_only_for_verified_fixes():
    verified = RegressionResult(
        original_run_id="r1",
        attack_blocked=True,
        legitimate_task_passed=True,
        fix_status=FixStatus.VERIFIED,
    )
    assert (
        reporting.proof_status(None, verified)["label"]
        == "ATTACK BLOCKED · LEGITIMATE TRANSFER PASSED"
    )

    regressed = RegressionResult(
        original_run_id="r1",
        attack_blocked=True,
        legitimate_task_passed=False,
        fix_status=FixStatus.BLOCKED_BUT_REGRESSION,
    )
    status = reporting.proof_status(None, regressed)
    assert status["label"] == "BLOCKED_BUT_REGRESSION"
    assert "ATTACK BLOCKED" not in status["label"]


# -- FR-RP-01..06: the real replay loop -----------------------------------
def test_replay_blocks_attack_and_passes_legitimate_transfer(orchestrator):
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])
    assert trials[0].verdict is Verdict.EXPLOIT_SUCCEEDED

    policy = orchestrator.propose_policy(trials[0].run_id)
    orchestrator.apply_policy(policy.policy_id)

    replay_run, regression = orchestrator.replay(trials[0].run_id)
    assert replay_run.verdict is Verdict.ATTEMPT_BLOCKED
    assert regression.attack_blocked is True
    assert regression.legitimate_task_passed is True
    assert regression.fix_status is FixStatus.VERIFIED
    assert regression.verification_status is VerificationStatus.VERIFIED


def test_replay_persists_a_receipt_with_state_equivalence(orchestrator):
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])
    policy = orchestrator.propose_policy(trials[0].run_id)
    orchestrator.apply_policy(policy.policy_id)
    replay_run, regression = orchestrator.replay(trials[0].run_id)

    receipts = [
        r
        for r in orchestrator.store.list_evidence(replay_run.run_id)
        if r.event_type == "replay_receipt"
    ]
    assert len(receipts) == 1
    receipt = receipts[0].details
    # FR-RP-06: the equivalence claim is recorded, not assumed.
    assert receipt["state_equivalence"]["equivalent"] is True
    assert receipt["state_equivalence"]["baseline_fingerprint"]
    assert receipt["outcome"]["fix_status"] == "VERIFIED"
    assert receipt["attack"]["attack_id"] == "AT-01"
    assert receipt["policy"]["applied_versions"] == [policy.version]
    # FR-RP-03: secrets never enter a receipt.
    serialized = json.dumps(receipt).lower()
    assert "private_key" not in serialized
    assert "mnemonic" not in serialized


def test_receipt_states_explicitly_when_no_transaction_was_submitted(orchestrator):
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])
    policy = orchestrator.propose_policy(trials[0].run_id)
    orchestrator.apply_policy(policy.policy_id)
    replay_run, _ = orchestrator.replay(trials[0].run_id)

    receipt = [
        r
        for r in orchestrator.store.list_evidence(replay_run.run_id)
        if r.event_type == "replay_receipt"
    ][0].details
    # The attack was blocked, so nothing reached the chain (FR-SB-05).
    assert receipt["transaction_evidence"]["submitted"] is False
    assert "No transaction was submitted" in receipt["transaction_evidence"]["note"]


def test_replay_reports_not_reproduced_when_policy_does_not_block(orchestrator):
    """A cap alone does not block AT-01; the verifier must say so."""
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])

    cap = Policy(
        type=PolicyType.MAX_AMOUNT,
        parameters={"max_amount": SAFE_TRANSFER_LIMIT, "decimals": 18},
    )
    orchestrator.store.save_policy(cap)
    orchestrator.apply_policy(cap.policy_id)

    replay_run, regression = orchestrator.replay(trials[0].run_id)
    assert replay_run.verdict is Verdict.EXPLOIT_SUCCEEDED
    assert regression.attack_blocked is False
    assert regression.fix_status is FixStatus.NOT_REPRODUCED
    assert regression.verification_status is VerificationStatus.FAILED


def test_repeated_replay_aggregates_before_and_after_rates(orchestrator):
    """FR-RP-05: one blocked replay is not a guarantee; report rates."""
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 2)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])
    assert len(trials) == 2
    policy = orchestrator.propose_policy(trials[0].run_id)
    orchestrator.apply_policy(policy.policy_id)

    replay_run, regression = orchestrator.replay(trials[0].run_id, repeat_count=3)
    details = regression.details
    assert details["repeat_count"] == 3
    assert len(details["replay_run_ids"]) == 3
    assert details["before_rate"] == 100.0
    assert details["after_rate"] == 100.0
    assert regression.fix_status is FixStatus.VERIFIED
    assert "not a general security guarantee" in details["note"]


def test_repeated_replay_rejects_zero_repeat_count(orchestrator):
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])
    with pytest.raises(Exception) as excinfo:
        orchestrator.replay(trials[0].run_id, repeat_count=0)
    assert "at least 1" in str(excinfo.value)


def test_comparison_is_tied_to_verified_records(orchestrator):
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])
    policy = orchestrator.propose_policy(trials[0].run_id)
    orchestrator.apply_policy(policy.policy_id)
    replay_run, _ = orchestrator.replay(trials[0].run_id)

    comparison = orchestrator.comparison(trials[0].run_id, replay_run.run_id)
    assert comparison["original"]["verdict"] == "EXPLOIT_SUCCEEDED"
    assert comparison["replay"]["verdict"] == "ATTEMPT_BLOCKED"
    assert comparison["state_equivalence"]["equivalent"] is True
    assert comparison["proof_status"]["label"] == (
        "ATTACK BLOCKED · LEGITIMATE TRANSFER PASSED"
    )


def test_comparison_rejects_a_missing_run(orchestrator):
    with pytest.raises(Exception):
        orchestrator.comparison("run-nope", "run-also-nope")


# -- FR-RE-06: the report -------------------------------------------------
def test_report_includes_metrics_coverage_and_limitations(orchestrator):
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01", "AT-02"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01", "AT-02"])
    policy = orchestrator.propose_policy(trials[0].run_id)
    orchestrator.apply_policy(policy.policy_id)
    orchestrator.replay(trials[0].run_id)

    report = orchestrator.build_report([run.run_id])
    metrics = report.metrics
    # ASR is scoped to the unprotected baseline (FR-RE-01).
    assert metrics["attack_success_rate"]["numerator"] == 2
    assert metrics["attack_success_rate"]["denominator"] == 2
    # DBR is scoped to the protected replay trials (FR-RE-02).
    assert metrics["defense_blocking_rate"]["numerator"] == 1
    assert metrics["defense_blocking_rate"]["denominator"] == 1
    coverage = report.sections["coverage"]
    assert coverage["baseline_trials"] == 2
    assert coverage["protected_trials"] == 1
    assert coverage["trials_total"] == 3  # 2 baselines + 1 replay run
    assert set(coverage["attacks_in_suite"]) == {"AT-01", "AT-02"}
    assert report.sections["per_attack"][0]["attack_id"] == "AT-01"
    assert report.sections["receipts"], "replay receipt should be in the report"
    assert report.limitations
    assert any("cannot establish comprehensive security" in x for x in report.limitations)
    assert report.integrity_hash and report.integrity_hash.startswith("0x")


def test_report_score_becomes_available_once_a_fix_is_verified(orchestrator):
    """FR-RE-04: the score needs protected trials and a legitimate regression."""
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])

    before = orchestrator.build_report([run.run_id])
    assert before.metrics["indicative_score"]["available"] is False

    policy = orchestrator.propose_policy(trials[0].run_id)
    orchestrator.apply_policy(policy.policy_id)
    orchestrator.replay(trials[0].run_id)

    after = orchestrator.build_report([run.run_id])
    score = after.metrics["indicative_score"]
    assert score["available"] is True
    assert score["value"] == 100.0
    assert after.sections["indicative_score"]["available"] is True


def test_report_lists_unsupported_scope_and_error_counts(orchestrator):
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-03"], 1)
    orchestrator.run_attack_trials(run, ["AT-03"])
    report = orchestrator.build_report([run.run_id])
    # AT-03 has no supported policy template, so scope must be stated.
    assert any("unsupported" in x for x in report.limitations)


def test_report_integrity_hash_detects_modification(orchestrator):
    """FR-DB-04: the hash must change if the canonical content changes.

    It is an integrity check over the report body, not a signature: it detects
    later modification and proves nothing about whether the evidence is true.
    """
    import hashlib

    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    orchestrator.run_attack_trials(run, ["AT-01"])
    report = orchestrator.build_report([run.run_id])

    def recompute(body):
        canonical = json.loads(json.dumps(body))
        canonical.pop("integrity_hash", None)
        return "0x" + hashlib.sha256(
            json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    body = report.model_dump(mode="json")
    assert recompute(body) == report.integrity_hash

    tampered = json.loads(json.dumps(body))
    tampered["metrics"]["attack_success_rate"]["numerator"] = 0
    assert recompute(tampered) != report.integrity_hash


# -- API surface ----------------------------------------------------------
def test_aggregate_summary_is_not_counted_as_an_extra_trial(orchestrator):
    """FR-RE-03: an aggregate must not inflate the legitimate-task denominator."""
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    trials = orchestrator.run_attack_trials(run, ["AT-01"])
    policy = orchestrator.propose_policy(trials[0].run_id)
    orchestrator.apply_policy(policy.policy_id)
    orchestrator.replay(trials[0].run_id, repeat_count=3)

    report = orchestrator.build_report([run.run_id])
    ltsr = report.metrics["legitimate_task_success_rate"]
    # Three replays ran, so three regressions — not four.
    assert ltsr["denominator"] == 3
    assert ltsr["numerator"] == 3

    regressions = report.sections["regressions"]
    assert sum(1 for r in regressions if r.get("aggregate")) == 1


def test_receipt_and_comparison_endpoints(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    trials = client.get(f"/api/scans/{run_id}/trials").json()
    trial_id = trials[0]["run_id"]
    policy = client.post(f"/api/scans/{run_id}/policies").json()["policy"]
    client.post(f"/api/policies/{policy['policy_id']}/apply")

    replay = client.post(f"/api/scans/{trial_id}/replay", json={}).json()
    replay_id = replay["replay_run"]["run_id"]
    assert replay["proof_status"]["label"] == (
        "ATTACK BLOCKED · LEGITIMATE TRANSFER PASSED"
    )

    receipt = client.get(f"/api/scans/{replay_id}/receipt")
    assert receipt.status_code == 200
    assert receipt.json()["receipt"]["state_equivalence"]["equivalent"] is True

    comparison = client.get(
        f"/api/scans/{trial_id}/comparison", params={"replay_run_id": replay_id}
    )
    assert comparison.status_code == 200
    body = comparison.json()
    assert body["original"]["verdict"] == "EXPLOIT_SUCCEEDED"
    assert body["replay"]["verdict"] == "ATTEMPT_BLOCKED"


def test_receipt_endpoint_404s_when_no_receipt_exists(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    trials = client.get(f"/api/scans/{run_id}/trials").json()
    response = client.get(f"/api/scans/{trials[0]['run_id']}/receipt")
    assert response.status_code == 404


def test_report_export_includes_new_sections_without_secrets(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    report_id = client.post("/api/reports", json={"run_ids": [run_id]}).json()["report"][
        "report_id"
    ]
    export = client.get(f"/api/reports/{report_id}/export")
    assert export.status_code == 200
    payload = export.json()
    assert "per_attack" in payload["sections"]
    assert "indicative_score" in payload["sections"]
    text = export.text.lower()
    assert "private_key" not in text
    assert "sk-" not in text
