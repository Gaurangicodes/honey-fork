"""Module 6 tests: persistence, versioning, evidence integrity and redaction.

These exercise the real SQLite store and the real orchestrator — no mocks — so
what is asserted is what a report reader would actually be able to recover.
"""

from __future__ import annotations

import json

import pytest

from agentcrash.core.attacks import all_attacks, get_attack
from agentcrash.core.errors import AgentCrashError
from agentcrash.core.hashing import canonical_hash, integrity_hash, verify_integrity
from agentcrash.core.models import (
    ErrorCode,
    PolicyStatus,
    PolicyType,
    RunStatus,
)
from agentcrash.core.store import Store


def _exploit(orchestrator, attack_id: str = "AT-01"):
    """Run one attack and return the verified exploit trial."""
    run = orchestrator.start_scan("agent-vulnerable-01", [attack_id], 1)
    trials = orchestrator.run_attack_trials(run, [attack_id])
    return run, trials[0]


# -- FR-DB-01: persist scan records, including failures ----------------------
def test_runs_persist_with_unique_ids_and_survive_a_reopen(tmp_path):
    path = tmp_path / "evidence.db"
    store = Store(path)
    from agentcrash.core.models import ScanRun

    first = ScanRun(agent_id="agent-vulnerable-01", attack_id="AT-01")
    second = ScanRun(agent_id="agent-vulnerable-01", attack_id="AT-02")
    store.save_run(first)
    store.save_run(second)
    assert first.run_id != second.run_id
    store.close()

    reopened = Store(path)
    ids = {r.run_id for r in reopened.list_runs()}
    assert {first.run_id, second.run_id} <= ids


def test_failed_run_is_retained_not_discarded(orchestrator):
    """Section 6.1: an incomplete run is kept with an error status."""
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    run.status = RunStatus.FAILED
    run.error_code = ErrorCode.SANDBOX_UNAVAILABLE.value
    orchestrator.store.save_run(run)

    stored = orchestrator.store.get_run(run.run_id)
    assert stored is not None
    assert stored.status is RunStatus.FAILED
    assert stored.error_code == ErrorCode.SANDBOX_UNAVAILABLE.value


def test_saving_a_run_twice_does_not_duplicate_it(orchestrator):
    run = orchestrator.start_scan("agent-vulnerable-01", ["AT-01"], 1)
    orchestrator.store.save_run(run)
    orchestrator.store.save_run(run)
    matches = [r for r in orchestrator.store.list_runs() if r.run_id == run.run_id]
    assert len(matches) == 1


# -- FR-DB-02: policy history is append-only and versions never collide -------
def test_repeated_proposals_do_not_inflate_the_version(orchestrator):
    """FR-DB-02: proposing the same fix twice must not mint a new version.

    The operator sees one rule. If each click bumped the version, the first rule
    they actually applied would read as "v7" in the header and in every report.
    """
    _, trial = _exploit(orchestrator)
    first = orchestrator.propose_policy(trial.run_id)
    second = orchestrator.propose_policy(trial.run_id)
    assert first.policy_id == second.policy_id
    assert first.version == second.version == "1"

    applied = orchestrator.apply_policy(first.policy_id)
    assert applied.status is PolicyStatus.APPLIED
    assert applied.version == "1"


def test_version_numbers_are_max_plus_one_not_a_count(orchestrator):
    """Versions are sparse once a proposal is superseded; counting collides."""
    from agentcrash.core.policy_registry import PolicyRegistry

    registry = PolicyRegistry(orchestrator.store)
    _, trial = _exploit(orchestrator)
    policy = orchestrator.propose_policy(trial.run_id)
    assert policy.version == "1"

    # Simulate a superseded version: v2 exists, then the row for v1 is gone.
    superseded = policy.model_copy(update={"policy_id": "policy-superseded", "version": "3"})
    orchestrator.store.save_policy(superseded)
    assert registry.next_version(PolicyType.RECIPIENT_ALLOWLIST) == "4"

    # Even with non-numeric history present, numbering stays numeric and safe.
    legacy = policy.model_copy(update={"policy_id": "policy-legacy", "version": "legacy"})
    orchestrator.store.save_policy(legacy)
    assert registry.next_version(PolicyType.RECIPIENT_ALLOWLIST) == "4"


def test_applied_policy_history_is_never_rewritten(orchestrator):
    """FR-DB-02: each application is a new record; history keeps its version."""
    _, trial = _exploit(orchestrator)
    first = orchestrator.apply_policy(orchestrator.propose_policy(trial.run_id).policy_id)
    applied_snapshot = orchestrator.store.get_policy(first.policy_id)
    assert applied_snapshot.status is PolicyStatus.APPLIED

    # A second, different allowlist becomes the effective one for its type...
    _, other_trial = _exploit(orchestrator, "AT-01")
    second_policy = orchestrator.propose_policy(other_trial.run_id)
    orchestrator.apply_policy(second_policy.policy_id)

    # ...but the first record still exists unchanged.
    assert orchestrator.store.get_policy(first.policy_id).status is PolicyStatus.APPLIED
    assert len(orchestrator.store.list_policies()) >= 2


# -- FR-DB-03: runs bind to an exact attack version --------------------------
def test_attack_definition_is_snapshotted_when_a_run_executes(orchestrator):
    _, trial = _exploit(orchestrator)
    stored = orchestrator.store.get_attack_definition("AT-01", "1.0.0")
    assert stored is not None
    assert stored.version == trial.attack_version
    assert stored.input_payload == get_attack("AT-01").input_payload


def test_stored_attack_version_is_immutable(orchestrator):
    """A later edit must not overwrite the definition a run executed."""
    _, trial = _exploit(orchestrator)
    original = orchestrator.store.get_attack_definition("AT-01", "1.0.0")

    edited = original.model_copy(update={"input_payload": "EDITED PAYLOAD"})
    orchestrator.store.save_attack_definition(edited)

    assert orchestrator.store.get_attack_definition("AT-01", "1.0.0").input_payload == (
        original.input_payload
    )


def test_report_still_resolves_an_attack_removed_from_the_library(orchestrator, monkeypatch):
    """FR-DB-03: editing the library must not silently alter an old report.

    The report is built twice. Between the two builds the in-process library
    stops offering the version the run executed, which is what a payload fix or
    a version bump looks like. The second report must still name the attack and
    must not drop it from the suite.
    """
    run, trial = _exploit(orchestrator)
    before = orchestrator.build_report([run.run_id])
    assert before.sections["coverage"]["attacks_in_suite"] == ["AT-01"]
    assert before.sections["suites"][0]["attack_version"] == "1.0.0"
    assert before.sections["suites"][0]["definition_available"] is True

    # The library no longer holds AT-01@1.0.0 (as if the case were revised).
    monkeypatch.setattr(
        "agentcrash.core.orchestrator.get_attack", lambda *a, **k: None
    )
    after = orchestrator.build_report([run.run_id])

    assert after.sections["coverage"]["attacks_in_suite"] == ["AT-01"]
    suite = after.sections["suites"][0]
    assert suite["attack_id"] == "AT-01"
    assert suite["attack_version"] == "1.0.0"
    # The snapshot recovered the real definition, so the text is still there.
    assert suite["name"] == "Poisoned token metadata"
    assert suite["definition_available"] is True


def test_report_marks_an_unrecoverable_attack_explicitly(orchestrator, monkeypatch):
    """NFR-11: an attack that cannot be resolved is labelled, not omitted."""
    run, _ = _exploit(orchestrator)
    monkeypatch.setattr(
        "agentcrash.core.orchestrator.get_attack", lambda *a, **k: None
    )
    # Also hide the snapshot, so nothing can recover the definition.
    monkeypatch.setattr(
        orchestrator.store, "get_attack_definition", lambda *a, **k: None
    )
    report = orchestrator.build_report([run.run_id])
    suite = report.sections["suites"][0]
    assert suite["definition_available"] is False
    assert suite["attack_id"] == "AT-01"
    assert "no longer available" in suite["note"]


def test_proposing_a_fix_for_an_unknown_attack_is_a_stable_error(orchestrator):
    """The stored snapshot is what makes this resolvable at all."""
    _, trial = _exploit(orchestrator)
    trial.attack_version = "9.9.9"
    orchestrator.store.save_run(trial)
    with pytest.raises(AgentCrashError) as exc:
        orchestrator.propose_policy(trial.run_id)
    assert exc.value.code is ErrorCode.ATTACK_NOT_FOUND


# -- FR-DB-04: evidence integrity -------------------------------------------
def test_every_evidence_record_is_stamped_and_verifies(orchestrator):
    """FR-DB-04: no record may be stored without a digest.

    The replay receipt previously bypassed the stamping path and was stored with
    integrity_hash=None, so the most important artifact in the system was the
    one a reader could not check.
    """
    _, trial = _exploit(orchestrator)
    policy = orchestrator.propose_policy(trial.run_id)
    orchestrator.apply_policy(policy.policy_id)
    orchestrator.replay(trial.run_id)

    records = orchestrator.store.list_all_evidence()
    assert records, "expected evidence to have been recorded"
    for record in records:
        assert record.integrity_hash, f"{record.event_type} was stored unstamped"
        assert verify_integrity(record), f"{record.event_type} failed its own digest"

    kinds = {r.event_type for r in records}
    assert "verdict" in kinds
    assert "replay_receipt" in kinds


def test_tampering_with_stored_evidence_is_detected(orchestrator):
    _, trial = _exploit(orchestrator)
    record = next(r for r in orchestrator.store.list_evidence(trial.run_id))
    assert verify_integrity(record)

    record.details = {**record.details, "tampered": True}
    assert not verify_integrity(record)


def test_verify_integrity_rejects_an_absent_digest():
    """A record with no digest must not be treated as intact."""
    assert not verify_integrity({"event_type": "verdict", "details": {}})
    assert not verify_integrity({"event_type": "verdict", "integrity_hash": ""})


def test_integrity_hash_ignores_its_own_field():
    """The digest must be recomputable from the stored body."""
    body = {"event_type": "verdict", "details": {"a": 1}}
    stamped = {**body, "integrity_hash": "0xdeadbeef"}
    assert integrity_hash(stamped) == canonical_hash(body)


def test_report_integrity_covers_the_whole_body(orchestrator):
    run, _ = _exploit(orchestrator)
    report = orchestrator.build_report([run.run_id])
    assert verify_integrity(report)
    report.metrics["test_errors"] = 99
    assert not verify_integrity(report)


def test_report_receipts_carry_their_evidence_digest(orchestrator):
    """FR-DB-04: an exported report can be checked against the store."""
    _, trial = _exploit(orchestrator)
    orchestrator.apply_policy(orchestrator.propose_policy(trial.run_id).policy_id)
    orchestrator.replay(trial.run_id)

    report = orchestrator.build_report([trial.run_id])
    receipts = report.sections["receipts"]
    assert receipts, "a replay must contribute a receipt to the report"
    for receipt in receipts:
        assert receipt["integrity_hash"].startswith("0x")


# -- Section 6.1: sandbox reset preserves historical evidence -----------------
def test_reset_preserves_history(orchestrator, manager):
    run, _ = _exploit(orchestrator)
    report = orchestrator.build_report([run.run_id])
    before = (len(orchestrator.store.list_runs()), len(orchestrator.store.list_reports()))

    manager.reset()

    after = (len(orchestrator.store.list_runs()), len(orchestrator.store.list_reports()))
    assert after == before
    assert orchestrator.store.get_report(report.report_id) is not None


# -- SR-05 / NFR-07: no secret reaches a response -----------------------------
def test_redaction_strips_secrets_from_nested_structures():
    from agentcrash.evidence.redaction import redact

    payload = {
        "api_key": "sk-abcdefghijklmnopqrstuvwxyz",
        "nested": {
            "private_key": "0x" + "a" * 64,
            "note": "token=supersecretvalue",
            "list": ["mnemonic: word word word word word word word word word word word word"],
        },
    }
    cleaned = json.dumps(redact(payload))
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in cleaned
    assert "a" * 64 not in cleaned
    assert "supersecretvalue" not in cleaned
    assert "word word word word" not in cleaned


def test_redaction_keeps_transaction_hashes_but_drops_private_keys():
    """SR-05 vs section 24: the two requirements pull in opposite directions.

    A 0x + 64-hex value is both a transaction hash and a private key. The
    dashboard must display the former (section 24) and must never leak the
    latter (SR-05), so the field name has to decide.
    """
    from agentcrash.evidence.redaction import redact, redact_text

    tx = "0x" + "ab" * 32
    key = "0x" + "11" * 32
    cleaned = redact(
        {
            "transaction_hashes": [tx],
            "tx_hash": tx,
            "integrity_hash": tx,
            "private_key": key,
            "seed_phrase": "word " * 12,
        }
    )
    assert cleaned["transaction_hashes"] == [tx]
    assert cleaned["tx_hash"] == tx
    assert cleaned["integrity_hash"] == tx
    assert cleaned["private_key"] == "[REDACTED]"
    assert cleaned["seed_phrase"] == "[REDACTED]"

    # Free text has no field name, so it keeps the strict rule.
    assert tx not in redact_text(f"key material {key}")
    assert "[REDACTED]" in redact_text(f"key material {key}")


def test_api_responses_preserve_transaction_evidence(client):
    """Section 24: the dashboard must be able to show the transaction hash."""
    created = client.post(
        "/api/scans?wait=true",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    )
    run_id = created.json()["run_id"]
    trials = client.get(f"/api/scans/{run_id}/trials").json()
    trial = trials[0]
    assert trial["verdict"] == "EXPLOIT_SUCCEEDED"
    assert trial["transaction_hashes"], "the exploit must have submitted a transaction"
    for tx_hash in trial["transaction_hashes"]:
        assert tx_hash.startswith("0x") and len(tx_hash) == 66
        assert tx_hash != "[REDACTED]"


def test_api_responses_are_redacted(client):
    """SR-05: runs, events and evidence are redacted at the response boundary."""
    created = client.post(
        "/api/scans?wait=true",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    )
    assert created.status_code == 202
    run_id = created.json()["run_id"]

    for path in (
        f"/api/scans/{run_id}",
        f"/api/scans/{run_id}/events",
        f"/api/scans/{run_id}/trials",
        "/api/scans",
    ):
        body = json.dumps(client.get(path).json())
        assert "private_key" not in body
        assert "seed_phrase" not in body


def test_evidence_integrity_endpoint_reports_intact(client):
    created = client.post(
        "/api/scans?wait=true",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    )
    run_id = created.json()["run_id"]
    payload = client.get("/api/evidence/integrity").json()
    assert payload["all_intact"] is True
    assert payload["failed"] == []
    assert payload["checked"] >= 1
    # The endpoint must not claim more than it can prove.
    assert "not a signature" in payload["note"]
    assert run_id  # the scan above is what produced the records being checked


def test_api_receipt_exposes_its_digest(client):
    created = client.post(
        "/api/scans?wait=true",
        json={"agent_id": "agent-vulnerable-01", "attack_ids": ["AT-01"], "repeat_count": 1},
    )
    run_id = created.json()["run_id"]
    trials = client.get(f"/api/scans/{run_id}/trials").json()
    trial_id = trials[0]["run_id"]

    proposed = client.post(f"/api/scans/{trial_id}/policies").json()
    assert proposed["policy"] is not None
    client.post(f"/api/policies/{proposed['policy']['policy_id']}/apply")
    replayed = client.post(f"/api/scans/{trial_id}/replay", json={"repeat_count": 1})
    assert replayed.status_code == 200
    replay_run_id = replayed.json()["replay_run"]["run_id"]

    receipt = client.get(f"/api/scans/{replay_run_id}/receipt").json()
    assert receipt["integrity_hash"].startswith("0x")
    assert receipt["receipt"]["kind"] == "replay_receipt"


def test_attack_library_is_seeded_into_the_store(client):
    """FR-AT-01/FR-DB-03: every library version is persisted at startup."""
    store: Store = client.app.state.store
    stored = {(a.attack_id, a.version) for a in store.list_attack_definitions()}
    expected = {(a.attack_id, a.version) for a in all_attacks()}
    assert expected <= stored
