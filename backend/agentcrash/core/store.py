"""Evidence store (Module 6 / architecture 20.2 Report & Evidence Service).

A small SQLite-backed repository. Pydantic models are serialized as JSON blobs
keyed by their identifiers, which keeps the schema stable while the domain
model evolves during the hackathon. Run IDs are unique and immutable; policy
versions are append-only (FR-DB-02, SR-08).
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel

from .models import (
    EnvironmentSnapshot,
    EvidenceRecord,
    Policy,
    RegressionResult,
    Report,
    RunEvent,
    ScanRun,
)

T = TypeVar("T", bound=BaseModel)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    attack_id TEXT NOT NULL,
    parent_run_id TEXT,
    run_type TEXT NOT NULL,
    status TEXT NOT NULL,
    verdict TEXT,
    policy_version TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_agent ON runs(agent_id);
CREATE INDEX IF NOT EXISTS idx_runs_parent ON runs(parent_run_id);

CREATE TABLE IF NOT EXISTS snapshots (
    snapshot_id TEXT PRIMARY KEY,
    run_id TEXT,
    payload TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policies (
    policy_id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    source_run_id TEXT,
    source_attack_id TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policies_attack ON policies(source_attack_id);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    integrity_hash TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, seq);

CREATE TABLE IF NOT EXISTS regressions (
    regression_id TEXT PRIMARY KEY,
    original_run_id TEXT NOT NULL,
    replay_run_id TEXT,
    policy_version TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_regressions_original ON regressions(original_run_id);

CREATE TABLE IF NOT EXISTS reports (
    report_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path = "data/agentcrash.db") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- runs ----------------------------------------------------------------
    def save_run(self, run: ScanRun) -> None:
        self._conn.execute(
            """INSERT INTO runs
               (run_id, agent_id, attack_id, parent_run_id, run_type, status,
                verdict, policy_version, payload)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(run_id) DO UPDATE SET
                 status=excluded.status, verdict=excluded.verdict,
                 policy_version=excluded.policy_version, payload=excluded.payload""",
            (
                run.run_id,
                run.agent_id,
                run.attack_id,
                run.parent_run_id,
                run.run_type.value,
                run.status.value,
                run.verdict.value if run.verdict else None,
                run.policy_version,
                run.model_dump_json(),
            ),
        )
        self._conn.commit()

    def get_run(self, run_id: str) -> ScanRun | None:
        row = self._conn.execute(
            "SELECT payload FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
        return ScanRun.model_validate_json(row["payload"]) if row else None

    def list_runs(self, limit: int = 50) -> list[ScanRun]:
        rows = self._conn.execute(
            "SELECT payload FROM runs ORDER BY rowid DESC LIMIT ?", (limit,)
        ).fetchall()
        return [ScanRun.model_validate_json(r["payload"]) for r in rows]

    def list_child_runs(self, parent_run_id: str) -> list[ScanRun]:
        rows = self._conn.execute(
            "SELECT payload FROM runs WHERE parent_run_id=? ORDER BY rowid ASC",
            (parent_run_id,),
        ).fetchall()
        return [ScanRun.model_validate_json(r["payload"]) for r in rows]

    # -- snapshots -----------------------------------------------------------
    def save_snapshot(self, snapshot: EnvironmentSnapshot) -> None:
        self._conn.execute(
            """INSERT INTO snapshots (snapshot_id, run_id, payload) VALUES (?,?,?)
               ON CONFLICT(snapshot_id) DO UPDATE SET payload=excluded.payload""",
            (snapshot.snapshot_id, snapshot.run_id, snapshot.model_dump_json()),
        )
        self._conn.commit()

    def get_snapshot(self, snapshot_id: str) -> EnvironmentSnapshot | None:
        row = self._conn.execute(
            "SELECT payload FROM snapshots WHERE snapshot_id=?", (snapshot_id,)
        ).fetchone()
        return EnvironmentSnapshot.model_validate_json(row["payload"]) if row else None

    # -- policies ------------------------------------------------------------
    def save_policy(self, policy: Policy) -> None:
        self._conn.execute(
            """INSERT INTO policies
               (policy_id, type, version, status, source_run_id, source_attack_id, payload)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(policy_id) DO UPDATE SET
                 status=excluded.status, payload=excluded.payload""",
            (
                policy.policy_id,
                policy.type.value,
                policy.version,
                policy.status.value,
                policy.source_run_id,
                policy.source_attack_id,
                policy.model_dump_json(),
            ),
        )
        self._conn.commit()

    def get_policy(self, policy_id: str) -> Policy | None:
        row = self._conn.execute(
            "SELECT payload FROM policies WHERE policy_id=?", (policy_id,)
        ).fetchone()
        return Policy.model_validate_json(row["payload"]) if row else None

    def list_policies(self) -> list[Policy]:
        rows = self._conn.execute(
            "SELECT payload FROM policies ORDER BY rowid ASC"
        ).fetchall()
        return [Policy.model_validate_json(r["payload"]) for r in rows]

    def latest_applied_policy(self) -> Policy | None:
        row = self._conn.execute(
            """SELECT payload FROM policies WHERE status='applied'
               ORDER BY rowid DESC LIMIT 1"""
        ).fetchone()
        return Policy.model_validate_json(row["payload"]) if row else None

    # -- evidence ------------------------------------------------------------
    def save_evidence(self, record: EvidenceRecord) -> None:
        self._conn.execute(
            """INSERT INTO evidence
               (evidence_id, run_id, event_type, integrity_hash, payload)
               VALUES (?,?,?,?,?)
               ON CONFLICT(evidence_id) DO UPDATE SET payload=excluded.payload""",
            (
                record.evidence_id,
                record.run_id,
                record.event_type,
                record.integrity_hash,
                record.model_dump_json(),
            ),
        )
        self._conn.commit()

    def list_evidence(self, run_id: str) -> list[EvidenceRecord]:
        rows = self._conn.execute(
            "SELECT payload FROM evidence WHERE run_id=? ORDER BY rowid ASC", (run_id,)
        ).fetchall()
        return [EvidenceRecord.model_validate_json(r["payload"]) for r in rows]

    # -- events --------------------------------------------------------------
    def save_event(self, event: RunEvent) -> None:
        self._conn.execute(
            """INSERT INTO events (event_id, run_id, seq, payload) VALUES (?,?,?,?)
               ON CONFLICT(event_id) DO UPDATE SET payload=excluded.payload""",
            (event.event_id, event.run_id, event.seq, event.model_dump_json()),
        )
        self._conn.commit()

    def list_events(self, run_id: str) -> list[RunEvent]:
        rows = self._conn.execute(
            "SELECT payload FROM events WHERE run_id=? ORDER BY seq ASC", (run_id,)
        ).fetchall()
        return [RunEvent.model_validate_json(r["payload"]) for r in rows]

    # -- regressions ---------------------------------------------------------
    def save_regression(self, result: RegressionResult) -> None:
        self._conn.execute(
            """INSERT INTO regressions
               (regression_id, original_run_id, replay_run_id, policy_version, payload)
               VALUES (?,?,?,?,?)
               ON CONFLICT(regression_id) DO UPDATE SET payload=excluded.payload""",
            (
                result.regression_id,
                result.original_run_id,
                result.replay_run_id,
                result.policy_version,
                result.model_dump_json(),
            ),
        )
        self._conn.commit()

    def list_regressions(self, original_run_id: str) -> list[RegressionResult]:
        rows = self._conn.execute(
            "SELECT payload FROM regressions WHERE original_run_id=? ORDER BY rowid ASC",
            (original_run_id,),
        ).fetchall()
        return [RegressionResult.model_validate_json(r["payload"]) for r in rows]

    # -- reports -------------------------------------------------------------
    def save_report(self, report: Report) -> None:
        self._conn.execute(
            """INSERT INTO reports (report_id, payload) VALUES (?,?)
               ON CONFLICT(report_id) DO UPDATE SET payload=excluded.payload""",
            (report.report_id, report.model_dump_json()),
        )
        self._conn.commit()

    def get_report(self, report_id: str) -> Report | None:
        row = self._conn.execute(
            "SELECT payload FROM reports WHERE report_id=?", (report_id,)
        ).fetchone()
        return Report.model_validate_json(row["payload"]) if row else None

    def list_reports(self) -> list[Report]:
        rows = self._conn.execute(
            "SELECT payload FROM reports ORDER BY rowid DESC"
        ).fetchall()
        return [Report.model_validate_json(r["payload"]) for r in rows]
