"""REST API (SRS section 7).

Endpoint names follow the proposed contracts. Module 2's endpoints are the
sandbox lifecycle, the scan/verification pipeline and the evidence/report
reads; the policy and replay endpoints are included because Module 2 owns the
transaction-boundary enforcement and the before/after proof.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, FastAPI, Request
from fastapi.responses import JSONResponse

from ..core.agents import agent_registry
from ..core.attacks import all_attacks
from ..core.errors import AgentCrashError
from ..core.models import ErrorCode, ScanRequest
from ..core.orchestrator import Orchestrator
from ..core.store import Store
from ..evidence.redaction import redact
from ..sandbox.manager import SandboxManager, default_demo_environment


def build_state() -> tuple[Store, Orchestrator, SandboxManager]:
    store = Store()
    environment = default_demo_environment()
    manager = SandboxManager(environment)
    orchestrator = Orchestrator(store, environment, manager)
    return store, orchestrator, manager


def create_app() -> FastAPI:
    store, orchestrator, manager = build_state()
    app = FastAPI(title="AgentCrash Replay API", version="0.2.0")
    app.state.store = store
    app.state.orchestrator = orchestrator
    app.state.manager = manager
    router = APIRouter(prefix="/api")

    @app.exception_handler(AgentCrashError)
    async def _handle_error(_: Request, exc: AgentCrashError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

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
        }

    # -- agents & attacks ----------------------------------------------------
    @router.get("/agents")
    def list_agents() -> list[dict[str, Any]]:
        return [a.model_dump(mode="json") for a in agent_registry()]

    @router.get("/attacks")
    def list_attacks() -> list[dict[str, Any]]:
        return [a.model_dump(mode="json") for a in all_attacks()]

    # -- scans ---------------------------------------------------------------
    @router.post("/scans")
    def start_scan(request: ScanRequest) -> dict[str, Any]:
        run = orchestrator.start_scan(
            request.agent_id, request.attack_ids, request.repeat_count
        )
        trials = orchestrator.run_attack_trials(run, request.attack_ids)
        return {
            "run_id": run.run_id,
            "status": run.status.value,
            "agent_id": run.agent_id,
            "total_trials": len(request.attack_ids) * request.repeat_count,
            "completed_trials": len(trials),
            "trial_run_ids": [t.run_id for t in trials],
        }

    @router.get("/scans")
    def list_scans(limit: int = 50) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in store.list_runs(limit=limit)]

    @router.get("/scans/{run_id}")
    def get_scan(run_id: str) -> dict[str, Any]:
        run = _require_run(store, run_id)
        children = store.list_child_runs(run_id)
        return {
            "run": run.model_dump(mode="json"),
            "child_runs": [c.model_dump(mode="json") for c in children],
            "evidence": [e.model_dump(mode="json") for e in store.list_evidence(run_id)],
        }

    @router.get("/scans/{run_id}/events")
    def get_events(run_id: str) -> list[dict[str, Any]]:
        _require_run(store, run_id)
        return [e.model_dump(mode="json") for e in store.list_events(run_id)]

    @router.get("/scans/{run_id}/trials")
    def get_trials(run_id: str) -> list[dict[str, Any]]:
        _require_run(store, run_id)
        return [t.model_dump(mode="json") for t in store.list_child_runs(run_id)]

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
            "policy": policies[0].model_dump(mode="json"),
            "policies": [p.model_dump(mode="json") for p in policies],
        }

    @router.post("/policies/{policy_id}/apply")
    def apply_policy(policy_id: str) -> dict[str, Any]:
        policy = orchestrator.apply_policy(policy_id)
        return {"policy": policy.model_dump(mode="json")}

    @router.get("/policies")
    def list_policies() -> list[dict[str, Any]]:
        return [p.model_dump(mode="json") for p in store.list_policies()]

    # -- replay --------------------------------------------------------------
    @router.post("/scans/{run_id}/replay")
    def replay(run_id: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        body = body or {}
        replay_run, regression = orchestrator.replay(
            run_id,
            policy_id=body.get("policy_id"),
            legitimate_recipient=body.get("legitimate_recipient"),
            legitimate_amount=body.get("legitimate_amount"),
        )
        return {
            "replay_run": replay_run.model_dump(mode="json"),
            "regression": regression.model_dump(mode="json"),
            "proof_status": _proof_status(replay_run, regression),
        }

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
        return {"snapshot": snapshot.model_dump(mode="json")}

    app.include_router(router)
    return app


def _require_run(store: Store, run_id: str):
    run = store.get_run(run_id)
    if run is None:
        raise AgentCrashError(ErrorCode.RUN_NOT_FOUND, f"No run {run_id}", resource_id=run_id)
    return run


def _proof_status(replay_run, regression) -> dict[str, Any]:
    """FR-RE-07: proof stamp derived from persisted verifier results."""
    from ..core.models import FixStatus

    if regression.fix_status is FixStatus.VERIFIED:
        label = "ATTACK BLOCKED · LEGITIMATE TRANSFER PASSED"
    else:
        label = regression.fix_status.value
    return {
        "label": label,
        "fix_status": regression.fix_status.value,
        "replay_verdict": replay_run.verdict.value if replay_run.verdict else None,
        "attack_blocked": regression.attack_blocked,
        "legitimate_task_passed": regression.legitimate_task_passed,
    }


app = create_app()
