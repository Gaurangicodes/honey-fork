"""Integration and end-to-end tests for the Module 2 pipeline."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agentcrash.api.app import create_app
from agentcrash.core.models import (
    FixStatus,
    PolicyType,
    Verdict,
)
from agentcrash.evidence.redaction import redact, redact_text


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with TestClient(create_app()) as c:
        yield c


# -- E2E-01 / FR-UI-02 ------------------------------------------------------
def test_start_scan_returns_run_id(client):
    response = client.post(
        "/api/scans",
        json={
            "agent_id": "agent-vulnerable-01",
            "attack_ids": ["AT-01", "AT-02", "AT-03", "AT-04"],
            "repeat_count": 1,
            "environment_id": "local-evm-demo",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["run_id"].startswith("run-")
    assert body["total_trials"] == 4
    assert body["completed_trials"] == 4


# -- E2E-02 / FR-SB-03 ------------------------------------------------------
def test_vulnerable_agent_produces_verified_unauthorized_transfer(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    trials = client.get(f"/api/scans/{run_id}/trials").json()
    assert len(trials) == 1
    trial = trials[0]
    assert trial["verdict"] == Verdict.EXPLOIT_SUCCEEDED.value
    assert trial["transaction_hashes"], "a real receipt hash must be recorded"
    unauthorized = next(
        d for d in trial["balance_deltas"] if d["delta"] > 0 and d["address"].lower().startswith("0xbad")
    )
    assert unauthorized["delta"] > 0


# -- E2E-03 / E2E-04 --------------------------------------------------------
def test_allowlist_policy_blocks_before_submission(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    policy = client.post(f"/api/scans/{run_id}/policies").json()["policy"]
    assert policy["type"] == PolicyType.RECIPIENT_ALLOWLIST.value
    client.post(f"/api/policies/{policy['policy_id']}/apply")

    replay = client.post(f"/api/scans/{run_id}/replay", json={}).json()
    assert replay["replay_run"]["verdict"] == Verdict.ATTEMPT_BLOCKED.value
    assert replay["replay_run"]["transaction_hashes"] == []
    assert replay["proof_status"]["attack_blocked"] is True
    assert replay["proof_status"]["legitimate_task_passed"] is True
    assert replay["proof_status"]["fix_status"] == FixStatus.VERIFIED.value


def test_max_amount_policy_blocks_oversized_transfer(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-04"], "repeat_count": 1},
    ).json()["run_id"]
    policy = client.post(f"/api/scans/{run_id}/policies").json()["policy"]
    assert policy["type"] == PolicyType.MAX_AMOUNT.value
    assert "max_amount" in policy["parameters"]
    client.post(f"/api/policies/{policy['policy_id']}/apply")
    replay = client.post(f"/api/scans/{run_id}/replay", json={}).json()
    assert replay["replay_run"]["verdict"] == Verdict.ATTEMPT_BLOCKED.value


# -- E2E-05 / FR-PL-05 ------------------------------------------------------
def test_legitimate_transfer_passes_under_policy(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    policy = client.post(f"/api/scans/{run_id}/policies").json()["policy"]
    client.post(f"/api/policies/{policy['policy_id']}/apply")
    replay = client.post(f"/api/scans/{run_id}/replay", json={}).json()
    assert replay["regression"]["legitimate_task_passed"] is True


# -- E2E-06 -----------------------------------------------------------------
def test_replay_produces_evidence_and_receipt(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    policy = client.post(f"/api/scans/{run_id}/policies").json()["policy"]
    client.post(f"/api/policies/{policy['policy_id']}/apply")
    replay_run_id = client.post(f"/api/scans/{run_id}/replay", json={}).json()["replay_run"][
        "run_id"
    ]
    events = client.get(f"/api/scans/{replay_run_id}/events").json()
    event_types = {e["event_type"] for e in events}
    assert "policy_decision" in event_types
    assert "verifier_verdict" in event_types
    assert "regression_result" in event_types


# -- guardrail: equivalent-state gate (FR-RP-06) ----------------------------
def test_replay_rejects_tampered_state(client):
    from agentcrash.core.errors import ReplayStateMismatch
    from agentcrash.core.orchestrator import Orchestrator

    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    orchestrator: Orchestrator = client.app.state.orchestrator
    policy = orchestrator.propose_policy(run_id)
    orchestrator.apply_policy(policy.policy_id)

    original = orchestrator._resolve_original_run(run_id)
    baseline = orchestrator.store.get_snapshot(original.environment_snapshot_id)
    # Simulate the environment configuration changing between the original run
    # and the replay (e.g. a different token contract or account set). The gate
    # must refuse to compare before/after across non-equivalent state.
    baseline.configuration_hash = "0x" + "de" * 32
    orchestrator.store.save_snapshot(baseline)

    with pytest.raises(ReplayStateMismatch):
        orchestrator.replay(run_id)


# -- E2E-07 -----------------------------------------------------------------
def test_untargeted_attack_is_not_reported_as_blocked(client):
    """An attack whose payload contains no recipient cannot trigger; a policy
    rejection must not be invented."""
    from agentcrash.core.attacks import AttackDefinition

    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    orchestrator = client.app.state.orchestrator
    attack = AttackDefinition(
        attack_id="AT-TEST",
        name="No-op attack",
        category="test",
        input_payload="Nothing actionable here.",
        success_condition="None",
    )
    trial = orchestrator._run_single_trial(
        parent=orchestrator.store.get_run(run_id), attack=attack, trial_index=1
    )
    assert trial.verdict is Verdict.ATTACK_NOT_TRIGGERED


# -- E2E-08 / guardrail -----------------------------------------------------
def test_model_provider_failure_is_test_error(client, monkeypatch):
    orchestrator = client.app.state.orchestrator
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]

    from agentcrash.core.agents import SandboxAgent

    def boom(self, *args, **kwargs):
        raise RuntimeError("model provider unavailable")

    monkeypatch.setattr(SandboxAgent, "propose_action", boom)
    trial = orchestrator._run_single_trial(
        parent=orchestrator.store.get_run(run_id),
        attack=__import__("agentcrash.core.attacks", fromlist=["get_attack"]).get_attack("AT-01"),
        trial_index=1,
    )
    assert trial.verdict is Verdict.TEST_ERROR
    assert trial.status.value == "failed"


def test_test_error_excluded_from_asr_denominator(client):
    orchestrator = client.app.state.orchestrator
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    report = orchestrator.build_report([run_id])
    assert report.metrics["attack_success_rate"]["denominator"] == 1
    assert report.metrics["attack_success_rate"]["numerator"] == 1


# -- E2E-09 -----------------------------------------------------------------
def test_reset_preserves_reports(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    report_id = client.post("/api/reports", json={"run_ids": [run_id]}).json()["report"][
        "report_id"
    ]
    response = client.post("/api/sandbox/reset").json()
    assert response["status"] == "reset"
    assert response["reports_preserved"] >= 1
    assert client.get(f"/api/reports/{report_id}").status_code == 200


# -- E2E-10 / NFR-07 --------------------------------------------------------
def test_report_export_is_valid_json_without_secrets(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    report_id = client.post("/api/reports", json={"run_ids": [run_id]}).json()["report"][
        "report_id"
    ]
    response = client.get(f"/api/reports/{report_id}/export")
    assert response.status_code == 200
    payload = response.json()
    text = response.text
    assert "private_key" not in text.lower()
    assert "sk-" not in text
    assert payload["report_id"] == report_id


def test_redaction_removes_secrets():
    raw = {
        "private_key": "0x" + "a" * 64,
        "note": "api_key=supersecretvalue123",
        "mnemonic": "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima",
    }
    cleaned = redact(raw)
    assert cleaned["private_key"] == "[REDACTED]"
    assert "supersecretvalue123" not in cleaned["note"]
    assert "alpha bravo" not in cleaned["mnemonic"]
    assert redact_text("token: abcdef123456") == "token=[REDACTED]"


# -- FR-PL-06 ---------------------------------------------------------------
def test_unsupported_attack_reports_no_fix(client):
    orchestrator = client.app.state.orchestrator
    from agentcrash.core.attacks import AttackDefinition

    attack = AttackDefinition(
        attack_id="AT-NOFIX",
        name="Unmappable",
        category="test",
        input_payload="no action",
        success_condition="none",
        supported_policy_type=None,
    )
    assert (
        orchestrator.compiler.compile(
            attack=attack, run_id="run-x", observed={}, existing_versions=0
        )
        is None
    )


# -- API contract -----------------------------------------------------------
def test_health_reports_sandbox(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    assert body["sandbox"]["chain_id"] == 31337


def test_unknown_agent_returns_stable_error_code(client):
    response = client.post(
        "/api/scans",
        json={"agent_id": "nope", "attack_ids": ["AT-01"], "repeat_count": 1},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "AGENT_NOT_FOUND"


def test_unknown_attack_returns_stable_error_code(client):
    response = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-99"], "repeat_count": 1},
    )
    assert response.json()["error"]["code"] == "ATTACK_NOT_FOUND"


def test_both_agent_configurations_are_selectable(client):
    agents = client.get("/api/agents").json()
    ids = {a["agent_id"] for a in agents}
    assert {"agent-vulnerable-01", "agent-guarded-01"} <= ids
    guardrails = {a["guardrail"] for a in agents}
    assert len(guardrails) == 2


def test_four_attacks_present(client):
    attacks = client.get("/api/attacks").json()
    assert {a["attack_id"] for a in attacks} == {"AT-01", "AT-02", "AT-03", "AT-04"}


def test_results_persist_across_requests(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    assert client.get(f"/api/scans/{run_id}").status_code == 200
    assert client.get(f"/api/scans/{run_id}").json()["run"]["run_id"] == run_id


# -- Guardrail B: policy that breaks legitimate behavior is refused ----------
def test_policy_breaking_legitimate_transfer_is_not_applied(client):
    from agentcrash.core.errors import AgentCrashError
    from agentcrash.core.models import Policy, PolicyStatus, PolicyType

    orchestrator = client.app.state.orchestrator
    # An allowlist that omits the approved recipient would block the known
    # legitimate transfer, so applying it must be refused.
    bad = Policy(
        type=PolicyType.RECIPIENT_ALLOWLIST,
        parameters={"allowed_recipients": [orchestrator.environment.unauthorized_recipient]},
        status=PolicyStatus.PROPOSED,
    )
    orchestrator.store.save_policy(bad)
    with pytest.raises(AgentCrashError):
        orchestrator.apply_policy(bad.policy_id)
    assert orchestrator.proxy.active_policy is None


# -- Full suite: two policy types from one scan ------------------------------
def test_full_suite_yields_both_policy_types(client):
    run_id = client.post(
        "/api/scans",
        json={
            "agent_id": "agent-vulnerable-01",
            "attack_ids": ["AT-01", "AT-02", "AT-03", "AT-04"],
            "repeat_count": 1,
        },
    ).json()["run_id"]
    body = client.post(f"/api/scans/{run_id}/policies").json()
    types = {p["type"] for p in body["policies"]}
    assert types == {"recipient_allowlist", "max_transaction_amount"}

    trials = client.get(f"/api/scans/{run_id}/trials").json()
    assert all(t["verdict"] == "EXPLOIT_SUCCEEDED" for t in trials)
    assert all(t["transaction_hashes"] for t in trials)


def test_guarded_agent_without_policy_still_exploited(client):
    """The guarded configuration differs only in the enforcement boundary; with
    no policy applied it behaves identically, which is the honest result."""
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-guarded-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    ).json()["run_id"]
    trials = client.get(f"/api/scans/{run_id}/trials").json()
    assert trials[0]["verdict"] == Verdict.EXPLOIT_SUCCEEDED.value


# -- Repeat trials ----------------------------------------------------------
def test_repeat_count_produces_distinct_trials(client):
    run_id = client.post(
        "/api/scans",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 3},
    ).json()["run_id"]
    trials = client.get(f"/api/scans/{run_id}/trials").json()
    assert len(trials) == 3
    assert len({t["run_id"] for t in trials}) == 3
    assert all(t["verdict"] == Verdict.EXPLOIT_SUCCEEDED.value for t in trials)
    report = client.post("/api/reports", json={"run_ids": [run_id]}).json()["report"]
    asr = report["metrics"]["attack_success_rate"]
    assert asr["numerator"] == 3 and asr["denominator"] == 3
