"""REST API (SRS section 7).

Endpoint names follow the proposed contracts. Module 2's endpoints are the
sandbox lifecycle, the scan/verification pipeline and the evidence/report
reads; the policy and replay endpoints are included because Module 2 owns the
transaction-boundary enforcement and the before/after proof.
"""

from __future__ import annotations

import threading
from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from ..core.agents import agent_registry
from ..core.attacks import all_attacks, get_attack
from ..core.errors import AgentCrashError
from ..core.hashing import verify_integrity
from ..core.models import AgentConfiguration, ErrorCode, ScanRequest
from ..core.orchestrator import Orchestrator
from ..core.policy_registry import POLICY_TEMPLATES, template_for
from ..core.reporting import proof_status
from ..core.store import Store
from ..evidence.redaction import redact
from ..integrations import build_registry
from ..sandbox.manager import SandboxManager, default_demo_environment


def build_state() -> tuple[Store, Orchestrator, SandboxManager]:
    store = Store()
    environment = default_demo_environment()
    manager = SandboxManager(environment)
    orchestrator = Orchestrator(store, environment, manager)
    # Seed the persisted agent registry so a registered configuration survives a
    # restart and is visible in the dashboard (FR-AG-01).
    for config in agent_registry():
        if store.get_agent_config(config.agent_id) is None:
            store.save_agent_config(config)
    # Seed the versioned attack library (FR-AT-01). Persisting each version
    # means a run can always be resolved back to the definition it executed,
    # even after the library is edited (FR-DB-03).
    for attack in all_attacks():
        store.save_attack_definition(attack)
    return store, orchestrator, manager


def create_app() -> FastAPI:
    store, orchestrator, manager = build_state()
    app = FastAPI(title="AgentCrash Replay API", version="0.2.0")
    app.state.store = store
    app.state.orchestrator = orchestrator
    app.state.manager = manager
    # Optional ecosystem adapters (SRS 20.6). Built unconditionally so the
    # dashboard can show a disabled adapter and its setup steps; nothing here
    # calls out until an endpoint below asks it to.
    app.state.integrations = build_registry()
    router = APIRouter(prefix="/api")

    @app.exception_handler(AgentCrashError)
    async def _handle_error(_: Request, exc: AgentCrashError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    def _out(model: Any) -> dict[str, Any]:
        """Serialize a model and redact it (SR-05, NFR-07).

        Every read that returns a run, an event, evidence or a policy goes
        through here. Those payloads embed tool arguments and transcripts, which
        are exactly the fields a credential could reach, so redaction belongs at
        the response boundary rather than only on the report path.
        """
        body = model.model_dump(mode="json") if hasattr(model, "model_dump") else model
        return redact(body)

    # -- health --------------------------------------------------------------
    @router.get("/health")
    def health() -> dict[str, Any]:
        env = orchestrator.environment
        return {
            "status": "ok",
            "sandbox": {
                "environment_id": env.environment_id,
                "adapter": type(env.chain).__name__,
                "chain_id": env.chain.chain_id,
                "block_number": env.chain.block_number(),
                "token_contract": env.token_contract,
            },
            "active_policy_version": orchestrator.proxy.active_policy_version,
            "active_policy_versions": orchestrator.proxy.active_policy_versions,
            "active_policy_count": len(orchestrator.proxy.active_policies),
        }

    # -- agents & attacks ----------------------------------------------------
    @router.get("/agents")
    def list_agents() -> list[dict[str, Any]]:
        return [_out(a) for a in store.list_agent_configs()]

    @router.post("/agents", status_code=201)
    def register_agent(config: AgentConfiguration) -> dict[str, Any]:
        """FR-AG-01: register a sandbox agent configuration."""
        registered = orchestrator.agents.register(config)
        store.save_agent_config(registered)
        return {"agent": _out(registered)}

    @router.get("/agents/{agent_id}")
    def get_agent_config(agent_id: str) -> dict[str, Any]:
        config = store.get_agent_config(agent_id) or orchestrator.agents.get(agent_id)
        if config is None:
            raise AgentCrashError(
                ErrorCode.AGENT_NOT_FOUND, f"Unknown agent {agent_id}", resource_id=agent_id
            )
        return {"agent": _out(config)}

    @router.get("/tools")
    def list_tools() -> list[dict[str, Any]]:
        """FR-AG-03: the only tools an agent may invoke."""
        return [t.model_dump(mode="json") for t in orchestrator.tools.list_tools()]

    @router.get("/attacks")
    def list_attacks() -> list[dict[str, Any]]:
        return [a.model_dump(mode="json") for a in all_attacks()]

    @router.get("/attacks/{attack_id}")
    def get_attack_detail(attack_id: str) -> dict[str, Any]:
        attack = get_attack(attack_id)
        if attack is None:
            raise AgentCrashError(
                ErrorCode.ATTACK_NOT_FOUND, f"Unknown attack {attack_id}", resource_id=attack_id
            )
        return {"attack": attack.model_dump(mode="json")}

    # -- scans ---------------------------------------------------------------
    @router.post("/scans", status_code=202)
    def start_scan(request: ScanRequest, wait: bool = False) -> dict[str, Any]:
        """FR-UI-02: queue a scan and return its run id immediately.

        The work runs in a background thread so the dashboard can poll progress
        and stream events (FR-UI-03). `?wait=true` keeps the old synchronous
        behaviour for scripted callers and tests.
        """
        run = orchestrator.start_scan(
            request.agent_id, request.attack_ids, request.repeat_count
        )
        planned_total = len(request.attack_ids) * request.repeat_count
        if wait:
            trials = orchestrator.run_attack_trials(run, request.attack_ids)
            return _scan_accepted(
                run, trials, planned_total=planned_total, queued=False
            )
        _start_background_scan(orchestrator, run, request.attack_ids)
        return _scan_accepted(run, [], planned_total=planned_total, queued=True)

    @router.get("/scans")
    def list_scans(limit: int = 50) -> list[dict[str, Any]]:
        return [_out(r) for r in store.list_runs(limit=limit)]

    @router.get("/scans/{run_id}")
    def get_scan(run_id: str) -> dict[str, Any]:
        run = _require_run(store, run_id)
        children = store.list_child_runs(run_id)
        return {
            "run": _out(run),
            "child_runs": [_out(c) for c in children],
            "evidence": [_out(e) for e in store.list_evidence(run_id)],
        }

    @router.get("/scans/{run_id}/events")
    def get_events(run_id: str) -> list[dict[str, Any]]:
        _require_run(store, run_id)
        return [_out(e) for e in store.list_events(run_id)]

    @router.get("/scans/{run_id}/trials")
    def get_trials(run_id: str) -> list[dict[str, Any]]:
        _require_run(store, run_id)
        return [_out(t) for t in store.list_child_runs(run_id)]

    # -- policies ------------------------------------------------------------
    @router.post("/scans/{run_id}/policies")
    def propose_policy(run_id: str) -> dict[str, Any]:
        policies = orchestrator.propose_policies(run_id)
        if not policies:
            return {
                "policy": None,
                "policies": [],
                "message": (
                    "No automatic fix is available for this run. The attack did not "
                    "produce a verified exploit, or no supported policy template matches."
                ),
            }
        return {
            "policy": _out(policies[0]),
            "policies": [_out(p) for p in policies],
            "templates": [
                _template_dict(template_for(p.type))
                for p in policies
                if template_for(p.type) is not None
            ],
        }

    @router.post("/policies/{policy_id}/apply")
    def apply_policy(policy_id: str) -> dict[str, Any]:
        policy = orchestrator.apply_policy(policy_id)
        template = template_for(policy.type)
        return {
            "policy": _out(policy),
            "template": _template_dict(template) if template else None,
            "active_stack": [_out(p) for p in orchestrator.proxy.active_policies],
        }

    @router.get("/policies")
    def list_policies() -> list[dict[str, Any]]:
        return [_out(p) for p in store.list_policies()]

    @router.get("/policies/active")
    def active_policies() -> dict[str, Any]:
        """FR-PL-03: the applied stack currently enforced on every transaction."""
        stack = orchestrator.proxy.active_policies
        return {
            "active_policies": [_out(p) for p in stack],
            "versions": [p.version for p in stack],
            "count": len(stack),
        }

    @router.get("/policies/templates")
    def policy_templates() -> list[dict[str, Any]]:
        """FR-PL-06/FR-PL-07: the supported rule types and what each one blocks."""
        return [_template_dict(t) for t in POLICY_TEMPLATES.values()]

    @router.get("/policies/{policy_id}")
    def get_policy(policy_id: str) -> dict[str, Any]:
        policy = store.get_policy(policy_id)
        if policy is None:
            raise AgentCrashError(
                ErrorCode.POLICY_NOT_FOUND, f"No policy {policy_id}", resource_id=policy_id
            )
        template = template_for(policy.type)
        return {
            "policy": _out(policy),
            "template": _template_dict(template) if template else None,
        }

    # -- replay --------------------------------------------------------------
    @router.post("/scans/{run_id}/replay")
    def replay(run_id: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        body = body or {}
        replay_run, regression = orchestrator.replay(
            run_id,
            policy_id=body.get("policy_id"),
            legitimate_recipient=body.get("legitimate_recipient"),
            legitimate_amount=body.get("legitimate_amount"),
            repeat_count=int(body.get("repeat_count", 1)),
        )
        return {
            "replay_run": _out(replay_run),
            "regression": _out(regression),
            "proof_status": proof_status(replay_run, regression),
            "active_stack": [_out(p) for p in orchestrator.proxy.active_policies],
        }

    @router.get("/scans/{run_id}/receipt")
    def get_receipt(run_id: str) -> dict[str, Any]:
        """FR-RP-03: the replay receipt recorded for a replay run."""
        _require_run(store, run_id)
        receipts = [
            r for r in store.list_evidence(run_id) if r.event_type == "replay_receipt"
        ]
        if not receipts:
            raise AgentCrashError(
                ErrorCode.REPORT_NOT_FOUND,
                f"No replay receipt recorded for run {run_id}",
                resource_id=run_id,
                status_code=404,
            )
        record = receipts[-1]
        return {
            "receipt": redact(record.details),
            "integrity_hash": record.integrity_hash,
        }

    @router.get("/scans/{run_id}/comparison")
    def comparison(run_id: str, replay_run_id: str) -> dict[str, Any]:
        """FR-RP-02: before/after view for a replay of `run_id`."""
        return redact(orchestrator.comparison(run_id, replay_run_id))

    # -- reports -------------------------------------------------------------
    @router.post("/reports")
    def create_report(body: dict[str, Any]) -> dict[str, Any]:
        run_ids = body.get("run_ids") or []
        report = orchestrator.build_report(run_ids)
        return {"report": redact(report.model_dump(mode="json"))}

    @router.get("/reports/{report_id}")
    def get_report(report_id: str) -> dict[str, Any]:
        report = store.get_report(report_id)
        if report is None:
            raise AgentCrashError(
                ErrorCode.REPORT_NOT_FOUND, f"No report {report_id}", resource_id=report_id
            )
        return {"report": redact(report.model_dump(mode="json"))}

    @router.get("/reports/{report_id}/export")
    def export_report(report_id: str) -> JSONResponse:
        report = store.get_report(report_id)
        if report is None:
            raise AgentCrashError(
                ErrorCode.REPORT_NOT_FOUND, f"No report {report_id}", resource_id=report_id
            )
        payload = redact(report.model_dump(mode="json"))
        return JSONResponse(
            content=payload,
            headers={"Content-Disposition": f'attachment; filename="{report_id}.json"'},
        )

    @router.get("/evidence/integrity")
    def evidence_integrity() -> dict[str, Any]:
        """FR-DB-04: recheck every stored evidence digest.

        This detects modification of a stored record; it is an integrity check,
        not an audit. It says nothing about whether the evidence is true.
        """
        records = store.list_all_evidence()
        failed = [r.evidence_id for r in records if not verify_integrity(r)]
        return {
            "checked": len(records),
            "failed": failed,
            "all_intact": not failed,
            "note": (
                "Integrity hashes detect later modification of stored records. "
                "They are not a signature and do not prove the evidence is true."
            ),
        }

    # -- sandbox -------------------------------------------------------------
    @router.post("/sandbox/reset")
    def reset_sandbox() -> dict[str, Any]:
        snapshot = manager.reset()
        return {
            "status": "reset",
            "snapshot": snapshot.model_dump(mode="json"),
            "reports_preserved": len(store.list_reports()),
        }

    @router.get("/sandbox/state")
    def sandbox_state() -> dict[str, Any]:
        snapshot = manager.capture_state(
            run_id=None,
            policy_version=orchestrator.proxy.active_policy_version,
            attack_id=None,
        )
        return {
            "snapshot": snapshot.model_dump(mode="json"),
            "active_policy_versions": orchestrator.proxy.active_policy_versions,
        }

    # -- optional ecosystem adapters (SRS 20.6, FR-INT-01..05) ---------------
    #
    # These endpoints report and exercise the optional adapters. None of them is
    # required by the core proof loop, and each one answers honestly when its
    # adapter is disabled or unconfigured rather than returning a fabricated
    # result. No adapter can approve a policy or authorise a transfer.
    @router.get("/integrations")
    def list_integrations() -> dict[str, Any]:
        """FR-INT-01: every adapter's state, flag and setup steps."""
        return app.state.integrations.summary()

    @router.get("/integrations/{adapter}")
    def get_integration(adapter: str) -> dict[str, Any]:
        integration = app.state.integrations.get(adapter)
        if integration is None:
            raise AgentCrashError(
                ErrorCode.INTEGRATION_NOT_FOUND,
                f"Unknown integration {adapter}",
                resource_id=adapter,
            )
        return integration.status()

    @router.post("/integrations/socket/preflight")
    def socket_preflight(body: dict[str, Any] | None = None) -> dict[str, Any]:
        """FR-INT-02: real dependency preflight, or an honest not-run state."""
        body = body or {}
        integration = app.state.integrations.get("socket")
        purls = body.get("purls")
        if purls is None:
            purls = _default_preflight_purls()
        result = integration.preflight(purls, poll=bool(body.get("poll", False)))
        return _out(result.to_dict())

    @router.post("/integrations/tigergraph/ingest/{run_id}")
    def tigergraph_ingest(run_id: str) -> dict[str, Any]:
        """FR-INT-03: ingest one run's recorded events; local graph unaffected."""
        run = _require_run(store, run_id)
        integration = app.state.integrations.get("tigergraph")
        events = [e.model_dump(mode="json") for e in store.list_events(run.run_id)]
        result = integration.ingest_events(events, agent_id=run.agent_id)
        return _out(result.to_dict())

    @router.get("/integrations/dodo/summary")
    def dodo_summary() -> dict[str, Any]:
        """FR-INT-05: read-only billing summary. Performs no charge."""
        result = app.state.integrations.get("dodo").payment_summary()
        return _out(result.to_dict())

    @router.post("/integrations/wisprflow/parse")
    def wisprflow_parse(body: dict[str, Any]) -> dict[str, Any]:
        """FR-INT-04: recognise a voice command and require confirmation.

        Deliberately a *parse* endpoint. It cannot execute anything, and it
        refuses transcripts that try to approve a policy, sign a transaction or
        move funds.
        """
        result = app.state.integrations.get("wisprflow").parse(body.get("transcript", ""))
        return _out(result.to_dict())

    app.include_router(router)
    return app


def _scan_accepted(run, trials: list, *, planned_total: int, queued: bool) -> dict[str, Any]:
    """FR-UI-02: the accepted-scan response, with progress counters.

    `planned_total` comes from the request rather than from the trials that have
    finished, so a queued scan reports "0 of N" instead of "0 of 0".
    """
    return {
        "run_id": run.run_id,
        "status": run.status.value,
        "agent_id": run.agent_id,
        "queued": queued,
        "total_trials": planned_total,
        "completed_trials": len(trials),
        "trial_run_ids": [t.run_id for t in trials],
    }


def _start_background_scan(
    orchestrator: Orchestrator, run, attack_ids: list[str]
) -> None:
    """Run a scan off the request thread so progress and events can be polled.

    A daemon thread keeps the MVP single-process and dependency-free (SRS 5.1:
    no task queue for a four-day build). Failures are recorded by the
    orchestrator as a FAILED run rather than raised into the request.
    """

    def _work() -> None:
        orchestrator.run_attack_trials(run, attack_ids)

    threading.Thread(target=_work, name=f"scan-{run.run_id}", daemon=True).start()


def _require_run(store: Store, run_id: str):
    run = store.get_run(run_id)
    if run is None:
        raise AgentCrashError(ErrorCode.RUN_NOT_FOUND, f"No run {run_id}", resource_id=run_id)
    return run


def _template_dict(template) -> dict[str, Any]:
    """FR-PL-07: the plain-language contract of a policy type."""
    return {
        "type": template.policy_type.value,
        "label": template.label,
        "summary": template.summary,
        "parameters": list(template.parameters),
        "blocks": template.blocks,
        "legitimate_impact": template.legitimate_impact,
    }


def _default_preflight_purls() -> list[str]:
    """PURLs for the project's own dependency manifests (FR-INT-02).

    Scanning our own manifests is the honest default: it is a real preflight
    over packages this product actually loads, not a canned list of names. A
    missing manifest yields no PURLs, which the adapter reports as "no packages
    to scan" rather than as a clean result.
    """
    import re
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[3]
    purls: list[str] = []

    requirements = repo_root / "backend" / "requirements.txt"
    if requirements.exists():
        for raw in requirements.read_text().splitlines():
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            match = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*([<>=!~]=?\s*[^\s,;]+)?", line)
            if not match:
                continue
            name = match.group(1)
            version = (match.group(2) or "").strip()
            version = re.sub(r"^[<>=!~]+\s*", "", version).split(",")[0].strip()
            purls.append(f"pkg:pypi/{name.lower()}@{version}" if version else f"pkg:pypi/{name.lower()}")

    package_json = repo_root / "frontend" / "package.json"
    if package_json.exists():
        import json as _json

        manifest = _json.loads(package_json.read_text())
        for section in ("dependencies", "devDependencies"):
            for name, spec in (manifest.get(section) or {}).items():
                version = re.sub(r"^[\^~>=<\s]+", "", str(spec)).split(" ")[0].strip()
                purls.append(
                    f"pkg:npm/{name}@{version}" if version else f"pkg:npm/{name}"
                )
    return purls


app = create_app()
